{-# LANGUAGE BangPatterns #-}

-- | Managed wrapper around the Triple Pipeline handle.
--
-- A 'Pipeline' owns its libitb handle through a 'ForeignPtr' whose
-- finalizer calls @ITB_Triple_Free@, so an unreachable Pipeline is
-- released by the Haskell GC (libitb zeroes key material internally).
-- 'freePipeline' forces the release deterministically.
module ITB.Pipeline
  ( Pipeline
  , newPipeline
  , initPipeline
  , openPipeline
  , blob
  , rekey
  , closePipeline
  , freePipeline
  , encryptMessage
  , decryptMessage
  , encryptStreamOneShot
  , decryptStreamOneShot
  , registerProfile
    -- * Internal (used by "ITB.Stream")
  , withPipelineHandle
  , pipelineForeignPtr
  , retryOnce
  , outCap
  ) where

import Control.Exception (throwIO)
import Control.Monad (void)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Unsafe as BU
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Foreign.C.Types (CInt, CSize)
import Foreign.Concurrent (newForeignPtr)
import Foreign.ForeignPtr (ForeignPtr, finalizeForeignPtr, withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, intPtrToPtr, ptrToIntPtr)
import Foreign.Storable (peek, poke)
import Data.Word (Word8)

import ITB.Errors
import ITB.FFI
import ITB.Opts (Opts, emptyOpts, renderOpts)

-- | Floor capacity for blob output buffers (Init \/ Rekey).
blobCap :: Int
blobCap = 64 * 1024

-- | Pre-allocation formula for Message \/ one-shot stream outputs:
-- @payload * 5\/4 + 65536@.
outCap :: Int -> Int
outCap payload = payload + payload `div` 4 + 65536

-- | A Triple Pipeline session plus its exported blob bytes.
--
-- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
-- chunk, so plaintext of verified chunks is released before a later
-- chunk can fail authentication.
data Pipeline = Pipeline
  { pipeFP   :: !(ForeignPtr ())
  , pipeBlob :: !(IORef BS.ByteString)
  }

-- | The Pipeline's 'ForeignPtr'. Internal — 'ITB.Stream' references it
-- from a stream session's finalizer so the Pipeline handle outlives
-- every session opened on it.
pipelineForeignPtr :: Pipeline -> ForeignPtr ()
pipelineForeignPtr = pipeFP

-- | Runs an action with the raw libitb handle, keeping the Pipeline
-- alive for the duration of the call. Internal.
withPipelineHandle :: Pipeline -> (ITBHandle -> IO a) -> IO a
withPipelineHandle p f =
  withForeignPtr (pipeFP p) (f . fromIntegral . ptrToIntPtr)

mkPipeline :: ITBHandle -> BS.ByteString -> IO Pipeline
mkPipeline h blobBytes = do
  ref <- newIORef blobBytes
  fp <- newForeignPtr (intPtrToPtr (fromIntegral h))
                      (void (c_ITB_Triple_Free h))
  pure (Pipeline fp ref)

-- ── retry-once buffer discipline ─────────────────────────────────────

-- | Single dispatch site for every variable-size output buffer:
-- pre-allocate @cap@ bytes, and on @statusBufferTooSmall@ retry once
-- with the exact size the FFI reported — gated on the reported length
-- strictly exceeding the current capacity.
retryOnce :: Int -> (Ptr Word8 -> CSize -> Ptr CSize -> IO CInt) -> IO BS.ByteString
retryOnce cap call = do
  (rc, need, bs) <- attempt cap
  if fromIntegral rc == statusBufferTooSmall && need > cap
    then do
      (rc2, need2, bs2) <- attempt need
      check rc2
      pure (BS.take need2 bs2)
    else do
      check rc
      pure bs
  where
    attempt !n = do
      fp <- BSI.mallocByteString n
      alloca $ \lenP -> do
        poke lenP 0
        rc <- withForeignPtr fp $ \p -> call p (fromIntegral n) lenP
        need <- fromIntegral <$> peek lenP
        pure (rc, need, BSI.fromForeignPtr fp 0 (min need n))

-- | Passes a ByteString as a NUL-terminated C string (copied).
withCStr :: String -> (Ptr Word8 -> IO a) -> IO a
withCStr s f = BS.useAsCString (BC.pack s) (f . castPtr)

withOpts :: Opts -> (Ptr Word8 -> IO a) -> IO a
withOpts o f = BS.useAsCString (renderOpts o) (f . castPtr)

withBytes :: BS.ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withBytes bs f =
  BU.unsafeUseAsCStringLen bs $ \(p, n) -> f (castPtr p) (fromIntegral n)

-- ── construction ─────────────────────────────────────────────────────

-- | Convenience constructor with profile defaults: @Nothing@ starts a
-- fresh session ('initPipeline'), @Just blobBytes@ reconstructs one
-- from a session blob ('openPipeline' with blob-embedded masters).
newPipeline :: String -> Maybe BS.ByteString -> IO Pipeline
newPipeline profile Nothing   = initPipeline profile emptyOpts
newPipeline profile (Just bs) = openPipeline profile bs emptyOpts Nothing

-- | Constructs a fresh Pipeline against the named profile. On a
-- blob-buffer retry the Init re-runs and yields a fresh session (the
-- undersized attempt is closed by libitb before returning).
initPipeline :: String -> Opts -> IO Pipeline
initPipeline profile opts =
  withCStr profile $ \profileC ->
    withOpts opts $ \optsC ->
      alloca $ \handleP -> do
        poke handleP 0
        blobBytes <- retryOnce blobCap $ \buf cap lenP ->
          c_ITB_Triple_Init (castPtr profileC) (castPtr optsC)
                            buf cap lenP handleP
        h <- peek handleP
        mkPipeline h blobBytes

-- | Reconstructs a Pipeline from a blob produced by 'initPipeline' or
-- 'rekey'. The masters argument is @Nothing@ to use the blob-embedded
-- masters, or @Just (perm, wrap)@ to override them.
openPipeline
  :: String
  -> BS.ByteString
  -> Opts
  -> Maybe (BS.ByteString, BS.ByteString)
  -> IO Pipeline
openPipeline profile blobBytes opts masters = do
  case masters of
    Just (pm, wm) | BS.null pm || BS.null wm ->
      throwIO (ITBError statusBadInput "master override bytes must be non-empty")
    _ -> pure ()
  let (pm, wm, count) = case masters of
        Nothing       -> (BS.empty, BS.empty, 0 :: CSize)
        Just (p', w') -> (p', w', 2)
  withCStr profile $ \profileC ->
    withOpts opts $ \optsC ->
      withBytes blobBytes $ \blobP blobLen ->
        withBytes pm $ \pmP pmLen ->
          withBytes wm $ \wmP wmLen ->
            alloca $ \handleP -> do
              poke handleP 0
              rc <- c_ITB_Triple_Open (castPtr profileC) blobP blobLen
                                      (castPtr optsC) pmP pmLen wmP wmLen
                                      count handleP
              check rc
              h <- peek handleP
              mkPipeline h blobBytes

-- ── session management ───────────────────────────────────────────────

-- | The exported session bundle bytes for the receiver side.
blob :: Pipeline -> IO BS.ByteString
blob = readIORef . pipeBlob

-- | Rotates the parallax + wrapper masters and refreshes 'blob'. Must
-- not run concurrently with cipher calls or open stream sessions on
-- the same Pipeline.
rekey :: Pipeline -> BS.ByteString -> BS.ByteString -> IO ()
rekey p perm wrap = do
  prev <- readIORef (pipeBlob p)
  fresh <- withPipelineHandle p $ \h ->
    withBytes perm $ \pmP pmLen ->
      withBytes wrap $ \wmP wmLen ->
        retryOnce (max blobCap (BS.length prev)) $ \buf cap lenP ->
          c_ITB_Triple_Rekey h pmP pmLen wmP wmLen buf cap lenP
  writeIORef (pipeBlob p) fresh

-- | Zeroes the Pipeline's key material and marks it closed.
-- Idempotent; subsequent cipher calls fail with 'statusTripleClosed'.
closePipeline :: Pipeline -> IO ()
closePipeline p = withPipelineHandle p $ \h -> c_ITB_Triple_Close h >>= check

-- | Releases the Go-side handle now instead of waiting for GC.
-- Safe to call more than once.
freePipeline :: Pipeline -> IO ()
freePipeline = finalizeForeignPtr . pipeFP

-- ── cipher entries ───────────────────────────────────────────────────

-- | Single Message encrypt: one call, one self-contained wire.
encryptMessage :: Pipeline -> BS.ByteString -> IO BS.ByteString
encryptMessage = cipher c_ITB_Triple_EncryptMessage

-- | Receive-side counterpart of 'encryptMessage'.
decryptMessage :: Pipeline -> BS.ByteString -> IO BS.ByteString
decryptMessage = cipher c_ITB_Triple_DecryptMessage

-- | One-shot stream encrypt for callers holding the whole plaintext
-- in memory. For bounded-memory streaming use
-- 'ITB.Stream.encryptStream'.
encryptStreamOneShot :: Pipeline -> BS.ByteString -> IO BS.ByteString
encryptStreamOneShot = cipher c_ITB_Triple_EncryptStream

-- | Receive-side counterpart of 'encryptStreamOneShot'.
decryptStreamOneShot :: Pipeline -> BS.ByteString -> IO BS.ByteString
decryptStreamOneShot = cipher c_ITB_Triple_DecryptStream

-- | Shared body for the four buffer-in \/ buffer-out cipher entries.
cipher
  :: (ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt)
  -> Pipeline -> BS.ByteString -> IO BS.ByteString
cipher f p src =
  withPipelineHandle p $ \h ->
    withBytes src $ \srcP srcLen ->
      retryOnce (outCap (BS.length src)) $ \buf cap lenP ->
        f h srcP srcLen buf cap lenP

-- ── profile registration ─────────────────────────────────────────────

-- | Registers a user-defined Triple profile under the given name so
-- subsequent 'initPipeline' \/ 'openPipeline' calls resolve it. The
-- opts follow the register-profile grammar validated by Go (@mode@,
-- @width@, @innerHash@ \/ @innerHashes@, @keyBits@, @macName@,
-- @outerCipher@, @parallaxPalette@, @parallaxSegmentSize@,
-- @chunkSize@, @parallaxOn@, @wrapperOn@) — build them with
-- 'ITB.Opts.opt' plus the typed setters where key names coincide. A
-- duplicate name fails with 'statusProfileExists'.
registerProfile :: String -> Opts -> IO ()
registerProfile name opts =
  withCStr name $ \nameC ->
    withOpts opts $ \optsC -> do
      rc <- c_ITB_Triple_RegisterProfile (castPtr nameC) (castPtr optsC)
      check rc
