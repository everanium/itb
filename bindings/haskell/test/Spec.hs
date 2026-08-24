{-# LANGUAGE BangPatterns #-}

-- | hspec suite for the ITB Haskell binding: roster checks, Single
-- Message and incremental Streaming round trips, error mapping, the
-- large-plaintext pre-allocate\/retry path, rekey, profile
-- registration, and the stream session's GC parent-pin.
module Main (main) where

import Control.Concurrent (threadDelay)
import Control.Monad (forM_)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Bits (shiftL, shiftR, xor)
import Data.Word (Word8, Word64)
import System.Mem (performGC)
import Test.Hspec

import ITB

-- | Deterministic non-trivial payload (xorshift64 fill).
payload :: Int -> Word64 -> BS.ByteString
payload n seed = fst (BS.unfoldrN n step (seed * 2 + 1))
  where
    step :: Word64 -> Maybe (Word8, Word64)
    step !x =
      let a = x `xor` (x `shiftL` 13)
          b = a `xor` (a `shiftR` 7)
          c = b `xor` (b `shiftL` 17)
      in Just (fromIntegral c, c)

-- | Expects the action to throw an 'ITBError' whose status is one of
-- the given codes.
shouldFailWithStatus :: IO a -> [Int] -> IO ()
shouldFailWithStatus action codes =
  (action >> pure ()) `shouldThrow` \e -> statusCode e `elem` codes

main :: IO ()
main = hspec $ do
  describe "roster" $ do
    it "version is non-empty" $ do
      v <- version
      v `shouldNotBe` ""

    it "hashes are in canonical registry order" $ do
      roster <- hashes
      map fst roster
        `shouldBe` [ "areion256", "areion512", "blake2b256", "blake2b512"
                   , "blake2s", "blake3", "aescmac", "siphash24", "chacha20"
                   ]
      forM_ roster $ \(_, w) -> w `shouldSatisfy` (> 0)

    it "profiles list carries the shipped names" $ do
      forM_ [ "singlemsg-triple-mac-v1"
            , "singlemsg-triple-nomac-v1"
            , "streaming-aead-triple-mac-v1"
            , "streaming-noaead-triple-v1"
            ] $ \name -> profiles `shouldSatisfy` elem name

    it "runtime knobs answer queries" $ do
      -- Negative values query without changing.
      _ <- setMemoryLimit (-1)
      prev <- setGcPercent (-1)
      prev `shouldSatisfy` (/= minBound)

  describe "Single Message" $ do
    it "round-trips through blob hand-off (singlemsg-triple-mac-v1)" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "singlemsg-triple-mac-v1" (Just blobBytes)
      forM_ [1, 4096, 256 * 1024] $ \size -> do
        let plain = payload size (fromIntegral size)
        wire <- encryptMessage sender plain
        wire `shouldNotBe` plain
        back <- decryptMessage receiver wire
        back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

    it "round-trips a large plaintext (pattern P1, > 1 MiB)" $ do
      sender <- newPipeline "singlemsg-triple-nomac-v1" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "singlemsg-triple-nomac-v1" (Just blobBytes)
      let plain = payload (2 * 1024 * 1024 + 17) 3
      wire <- encryptMessage sender plain
      back <- decryptMessage receiver wire
      back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

  describe "Streaming" $ do
    it "round-trips incrementally (streaming-noaead-triple-v1)" $ do
      sender <- newPipeline "streaming-noaead-triple-v1" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "streaming-noaead-triple-v1" (Just blobBytes)
      let plain = payload (96 * 1024) 7

      -- Encrypt incrementally: 8 KiB writes, then end + drain.
      enc <- encryptStream sender
      forM_ (chunksOf 8192 plain) (writeStream enc)
      wire <- drainAll enc
      BS.length wire `shouldSatisfy` (> 0)
      freeStream enc

      -- Decrypt with pathological batch sizes (17-byte feed, 23-byte
      -- drain) across chunk boundaries.
      dec <- decryptStream receiver
      forM_ (chunksOf 17 wire) (writeStream dec)
      endStream dec
      let drainLoop acc = do
            (chunk, fin) <- readStream dec 23
            let acc' = chunk : acc
            if fin then pure (BS.concat (reverse acc')) else drainLoop acc'
      back <- drainLoop []
      back `shouldBe` plain
      freeStream dec
      freePipeline receiver
      freePipeline sender

    it "one-shot stream matches the incremental wire format" $ do
      sender <- newPipeline "streaming-noaead-triple-v1" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "streaming-noaead-triple-v1" (Just blobBytes)
      let plain = payload (64 * 1024 + 3) 11
      wire <- encryptStreamOneShot sender plain
      back <- decryptStreamOneShot receiver wire
      back `shouldBe` plain
      freePipeline receiver
      freePipeline sender

    it "pins its parent Pipeline against GC (session-parent pin)" $ do
      -- The Pipeline local goes out of scope with no other reference;
      -- the session record (and its finalizer) must keep the Go-side
      -- Pipeline handle alive.
      sess <- do
        pipe <- newPipeline "streaming-noaead-triple-v1" Nothing
        encryptStream pipe
      performGC
      threadDelay 50000
      performGC
      threadDelay 50000
      writeStream sess (BC.pack "still alive after parent went out of scope")
      wire <- drainAll sess
      BS.length wire `shouldSatisfy` (> 0)
      freeStream sess

  describe "error mapping" $ do
    it "unknown profile maps to statusBadInput" $
      newPipeline "no-such-profile" Nothing
        `shouldFailWithStatus` [statusBadInput]

    it "unknown opts key maps to statusBadInput" $
      -- Typoed key (lowercase s) — Go rejects unknown keys; the
      -- binding performs no validation of its own.
      initPipeline "singlemsg-triple-mac-v1" (opt "chunksize" "4096")
        `shouldFailWithStatus` [statusBadInput]

    it "tampered wire fails authentication" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "singlemsg-triple-mac-v1" (Just blobBytes)
      wire <- encryptMessage sender (payload 4096 21)
      let i = BS.length wire `div` 2
          tampered = BS.concat
            [ BS.take i wire
            , BS.singleton (BS.index wire i `xor` 0xFF)
            , BS.drop (i + 1) wire
            ]
      decryptMessage receiver tampered
        `shouldFailWithStatus` [statusMacFailure, statusDecryptFailed]
      freePipeline receiver
      freePipeline sender

    it "closed Pipeline maps to statusTripleClosed" $ do
      pipe <- newPipeline "singlemsg-triple-mac-v1" Nothing
      closePipeline pipe
      closePipeline pipe -- idempotent
      encryptMessage pipe (BC.pack "payload")
        `shouldFailWithStatus` [statusTripleClosed]
      freePipeline pipe

  describe "session management" $ do
    it "rekey refreshes the blob and the refreshed blob opens" $ do
      sender <- newPipeline "singlemsg-triple-mac-v1" Nothing
      blobBefore <- blob sender
      rekey sender (payload 32 5) (payload 32 6)
      blobAfter <- blob sender
      blobAfter `shouldNotBe` blobBefore
      receiver <- newPipeline "singlemsg-triple-mac-v1" (Just blobAfter)
      wire <- encryptMessage sender (BC.pack "post-rekey payload")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "post-rekey payload"
      freePipeline receiver
      freePipeline sender

    it "registerProfile round-trips and rejects a duplicate" $ do
      let profOpts = mconcat
            [ opt "mode" "singlemsg-nomac"
            , opt "width" "256"
            , opt "innerHashes"
                  "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256"
            , opt "keyBits" "1024"
            , opt "parallaxOn" "false"
            , opt "wrapperOn" "false"
            ]
      registerProfile "haskell-binding-test-mixed" profOpts
      sender <- newPipeline "haskell-binding-test-mixed" Nothing
      blobBytes <- blob sender
      receiver <- newPipeline "haskell-binding-test-mixed" (Just blobBytes)
      wire <- encryptMessage sender (BC.pack "custom profile")
      back <- decryptMessage receiver wire
      back `shouldBe` BC.pack "custom profile"
      registerProfile "haskell-binding-test-mixed" profOpts
        `shouldFailWithStatus` [statusProfileExists]
      freePipeline receiver
      freePipeline sender

  describe "opts builder" $ do
    it "renders typed setters as the expected query string" $ do
      let q = renderOpts $ mconcat
            [ permMaster (BS.pack [0xAB, 0x01])
            , wrapMaster (BS.pack [0xCD, 0xEF])
            , withParallax True
            , withWrapper False
            , nonceBits 512
            , keyBits 1024
            , innerHash "areion512"
            , parallaxPalette ["aescmac", "chacha20", "blake3"]
            ]
      q `shouldBe` BC.pack
        "pm=ab01&wm=cdef&withParallax=true&withWrapper=false&\
        \nonceBits=512&keyBits=1024&innerHash=areion512&\
        \parallaxPalette=aescmac,chacha20,blake3"

    it "percent-encodes bytes outside the URL-safe subset" $ do
      renderOpts (opt "mode" "a b&c=d%")
        `shouldBe` BC.pack "mode=a%20b%26c%3Dd%25"
      renderOpts emptyOpts `shouldBe` BC.pack ""

-- | Splits a ByteString into slices of at most @n@ bytes (zero-copy).
chunksOf :: Int -> BS.ByteString -> [BS.ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = BS.take n bs : chunksOf n (BS.drop n bs)
