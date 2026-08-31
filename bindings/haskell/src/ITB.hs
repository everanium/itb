-- | Thin Haskell proxy over the libitb shared library's Triple
-- Pipeline surface.
--
-- The package wraps the @ITB_Triple_*@ C ABI exported by
-- @cmd\/cshared@ (libitb.so) through @foreign import ccall@. Every
-- hash-name \/ MAC-name \/ cipher-name \/ profile-name is an opaque
-- string passed through to Go for validation; the binding carries no
-- ITB construction logic of its own.
--
-- > sender   <- newPipeline "singlemsg-triple-mac-v1" Nothing
-- > blobHere <- blob sender
-- > receiver <- newPipeline "singlemsg-triple-mac-v1" (Just blobHere)
-- > wire     <- encryptMessage sender "hello"
-- > plain    <- decryptMessage receiver wire   -- == "hello"
module ITB
  ( -- * Pipeline
    Pipeline
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
    -- * Incremental stream sessions
  , StreamEncryptor
  , StreamDecryptor
  , StreamSession
  , encryptStream
  , decryptStream
  , writeStream
  , endStream
  , readStream
  , drainAll
  , freeStream
    -- * Options
  , Opts
  , emptyOpts
  , renderOpts
  , opt
  , permMaster
  , wrapMaster
  , withParallax
  , withWrapper
  , maxWorkers
  , nonceBits
  , barrierFill
  , chunkSize
  , keyBits
  , parallaxSegmentSize
  , macName
  , innerHash
  , innerHashes
  , outerCipher
  , parallaxPalette
    -- * Errors
  , module ITB.Errors
    -- * Library roster and runtime knobs
  , version
  , hashes
  , profiles
  , setMemoryLimit
  , setGcPercent
  , bindingVersion
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Internal as BSI
import Data.Int (Int64)
import Foreign.C.Types (CChar, CInt, CSize)
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (peek, poke)

import ITB.Errors
import ITB.FFI
import ITB.Opts
import ITB.Pipeline
import ITB.Stream

-- | The binding's own version.
bindingVersion :: String
bindingVersion = "0.3.0"

-- | Returns the libitb library version string.
version :: IO String
version = readCStr c_ITB_Version

-- | The shipped hash primitive roster in canonical registry order,
-- as @(name, widthBits)@ pairs.
hashes :: IO [(String, Int)]
hashes = do
  n <- c_ITB_HashCount
  mapM row [0 .. n - 1]
  where
    row i = do
      name <- readCStr (c_ITB_HashName i)
      w <- c_ITB_HashWidth i
      pure (name, fromIntegral w)

-- | Built-in Triple profile names. The C ABI exposes no profile
-- enumeration; this list mirrors the shipped profile registry
-- (@triple\/profile.go@) and does not include profiles added at
-- runtime via 'registerProfile'.
profiles :: [String]
profiles =
  [ "streaming-aead-triple-mac-v1"
  , "streaming-noaead-triple-v1"
  , "singlemsg-triple-mac-v1"
  , "singlemsg-triple-nomac-v1"
  , "blob-triple-mac-v1"
  , "streaming-aead-triple-mac-mixed-v1"
  , "streaming-noaead-triple-mixed-v1"
  , "singlemsg-triple-mac-mixed-v1"
  , "singlemsg-triple-nomac-mixed-v1"
  ]

-- | Sets the Go runtime's soft heap limit in bytes and returns the
-- previous limit. A negative value queries without changing.
setMemoryLimit :: Int64 -> IO Int64
setMemoryLimit = c_ITB_SetMemoryLimit

-- | Sets the Go GC trigger percentage and returns the previous value.
-- A negative value queries without changing.
setGcPercent :: Int -> IO Int
setGcPercent = fmap fromIntegral . c_ITB_SetGCPercent . fromIntegral

-- | Two-phase read over the @(out, cap, *outLen)@ C-string contract:
-- probe with NULL \/ 0 for the required capacity, then read and
-- NUL-strip.
readCStr :: (Ptr CChar -> CSize -> Ptr CSize -> IO CInt) -> IO String
readCStr call = do
  need <- alloca $ \lenP -> do
    poke lenP 0
    rc <- call nullPtr 0 lenP
    if fromIntegral rc == statusOk || fromIntegral rc == statusBufferTooSmall
      then fromIntegral <$> peek lenP
      else check rc >> pure (0 :: Int)
  if need <= 1
    then pure ""
    else do
      fp <- BSI.mallocByteString need
      written <- alloca $ \lenP -> do
        poke lenP 0
        rc <- withForeignPtr fp $ \p ->
          call (castPtr p) (fromIntegral need) lenP
        check rc
        fromIntegral <$> peek lenP
      pure . BC.unpack . BS.take (max 0 (written - 1)) $
        BSI.fromForeignPtr fp 0 (min written need)
