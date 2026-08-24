{-# LANGUAGE ForeignFunctionInterface #-}

-- | Raw @foreign import ccall@ declarations over the libitb C ABI
-- (@dist\/linux-amd64\/libitb.h@). Handles are @uintptr_t@ values, not
-- pointers; every buffer crosses as @(ptr, len)@ with a @size_t@
-- out-param reporting the produced length. All imports are @safe@ —
-- libitb hosts a full Go runtime and cipher calls can run for a long
-- time, so the GHC capability must stay free to schedule other
-- Haskell threads (and to run GC) during a call.
module ITB.FFI
  ( ITBHandle
  , c_ITB_Version
  , c_ITB_LastError
  , c_ITB_SetMemoryLimit
  , c_ITB_SetGCPercent
  , c_ITB_HashCount
  , c_ITB_HashName
  , c_ITB_HashWidth
  , c_ITB_Triple_Init
  , c_ITB_Triple_Open
  , c_ITB_Triple_Rekey
  , c_ITB_Triple_Close
  , c_ITB_Triple_Free
  , c_ITB_Triple_EncryptMessage
  , c_ITB_Triple_DecryptMessage
  , c_ITB_Triple_EncryptStream
  , c_ITB_Triple_DecryptStream
  , c_ITB_Triple_RegisterProfile
  , c_ITB_Triple_EncryptStreamBegin
  , c_ITB_Triple_DecryptStreamBegin
  , c_ITB_Triple_StreamWrite
  , c_ITB_Triple_StreamEnd
  , c_ITB_Triple_StreamRead
  , c_ITB_Triple_StreamFree
  ) where

import Data.Int (Int64)
import Data.Word (Word8)
import Foreign.C.Types (CChar, CInt (..), CSize (..), CUIntPtr (..))
import Foreign.Ptr (Ptr)

-- | Opaque libitb handle (@uintptr_t@ on the C side).
type ITBHandle = CUIntPtr

-- ── library / runtime ───────────────────────────────────────────────

foreign import ccall safe "ITB_Version"
  c_ITB_Version :: Ptr CChar -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_LastError"
  c_ITB_LastError :: Ptr CChar -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_SetMemoryLimit"
  c_ITB_SetMemoryLimit :: Int64 -> IO Int64

foreign import ccall safe "ITB_SetGCPercent"
  c_ITB_SetGCPercent :: CInt -> IO CInt

-- ── hash registry iteration ─────────────────────────────────────────

foreign import ccall safe "ITB_HashCount"
  c_ITB_HashCount :: IO CInt

foreign import ccall safe "ITB_HashName"
  c_ITB_HashName :: CInt -> Ptr CChar -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_HashWidth"
  c_ITB_HashWidth :: CInt -> IO CInt

-- ── Triple Pipeline lifecycle ───────────────────────────────────────

foreign import ccall safe "ITB_Triple_Init"
  c_ITB_Triple_Init
    :: Ptr CChar        -- profile
    -> Ptr CChar        -- opts query string
    -> Ptr Word8        -- blob out
    -> CSize            -- blob cap
    -> Ptr CSize        -- blob len out
    -> Ptr ITBHandle    -- handle out
    -> IO CInt

foreign import ccall safe "ITB_Triple_Open"
  c_ITB_Triple_Open
    :: Ptr CChar        -- profile
    -> Ptr Word8        -- blob
    -> CSize            -- blob len
    -> Ptr CChar        -- opts query string
    -> Ptr Word8        -- perm master
    -> CSize            -- perm master len
    -> Ptr Word8        -- wrap master
    -> CSize            -- wrap master len
    -> CSize            -- masters count (0 or 2)
    -> Ptr ITBHandle    -- handle out
    -> IO CInt

foreign import ccall safe "ITB_Triple_Rekey"
  c_ITB_Triple_Rekey
    :: ITBHandle
    -> Ptr Word8 -> CSize        -- perm master
    -> Ptr Word8 -> CSize        -- wrap master
    -> Ptr Word8 -> CSize        -- blob out / cap
    -> Ptr CSize                 -- blob len out
    -> IO CInt

foreign import ccall safe "ITB_Triple_Close"
  c_ITB_Triple_Close :: ITBHandle -> IO CInt

foreign import ccall safe "ITB_Triple_Free"
  c_ITB_Triple_Free :: ITBHandle -> IO CInt

-- ── buffer-in / buffer-out cipher entries ───────────────────────────

foreign import ccall safe "ITB_Triple_EncryptMessage"
  c_ITB_Triple_EncryptMessage
    :: ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_Triple_DecryptMessage"
  c_ITB_Triple_DecryptMessage
    :: ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_Triple_EncryptStream"
  c_ITB_Triple_EncryptStream
    :: ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt

foreign import ccall safe "ITB_Triple_DecryptStream"
  c_ITB_Triple_DecryptStream
    :: ITBHandle -> Ptr Word8 -> CSize -> Ptr Word8 -> CSize -> Ptr CSize -> IO CInt

-- ── profile registration ────────────────────────────────────────────

foreign import ccall safe "ITB_Triple_RegisterProfile"
  c_ITB_Triple_RegisterProfile :: Ptr CChar -> Ptr CChar -> IO CInt

-- ── incremental stream sessions ─────────────────────────────────────

foreign import ccall safe "ITB_Triple_EncryptStreamBegin"
  c_ITB_Triple_EncryptStreamBegin :: ITBHandle -> Ptr ITBHandle -> IO CInt

foreign import ccall safe "ITB_Triple_DecryptStreamBegin"
  c_ITB_Triple_DecryptStreamBegin :: ITBHandle -> Ptr ITBHandle -> IO CInt

foreign import ccall safe "ITB_Triple_StreamWrite"
  c_ITB_Triple_StreamWrite :: ITBHandle -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall safe "ITB_Triple_StreamEnd"
  c_ITB_Triple_StreamEnd :: ITBHandle -> IO CInt

foreign import ccall safe "ITB_Triple_StreamRead"
  c_ITB_Triple_StreamRead
    :: ITBHandle -> Ptr Word8 -> CSize -> Ptr CSize -> Ptr CInt -> IO CInt

foreign import ccall safe "ITB_Triple_StreamFree"
  c_ITB_Triple_StreamFree :: ITBHandle -> IO CInt
