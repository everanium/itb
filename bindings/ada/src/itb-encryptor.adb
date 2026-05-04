--  Itb.Encryptor body — Easy Mode encryptor implementation.

with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces.C;
with Interfaces.C.Strings;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Encryptor is

   use type Itb.Sys.Handle;

   ---------------------------------------------------------------------
   --  Internal helpers
   ---------------------------------------------------------------------

   procedure Free_Cache is
     new Ada.Unchecked_Deallocation
       (Object => Byte_Array, Name => Byte_Array_Access);

   --  Empty-Byte_Array helper. Stream_Element_Array indexing starts at
   --  any base; the canonical "no data" form across the binding is
   --  (1 .. 0).
   function Empty return Byte_Array is
   begin
      return Byte_Array'(1 .. 0 => 0);
   end Empty;

   --  Constructs the C-string handle to pass for an optional input
   --  string: Ada empty "" maps to libitb's Null_String sentinel
   --  (meaning "no value / use default" semantics on the FFI side);
   --  any non-empty string is allocated via Strings.New_String and
   --  must be paired with Strings.Free by the caller.
   function To_C_String_Or_Null
     (S : String) return Interfaces.C.Strings.chars_ptr is
   begin
      if S = "" then
         return Itb.Sys.Null_String;
      else
         return Interfaces.C.Strings.New_String (S);
      end if;
   end To_C_String_Or_Null;

   procedure Free_If_Allocated
     (Ptr : in out Interfaces.C.Strings.chars_ptr) is
      use type Interfaces.C.Strings.chars_ptr;
   begin
      if Ptr /= Itb.Sys.Null_String then
         Interfaces.C.Strings.Free (Ptr);
      end if;
   end Free_If_Allocated;

   --  Default MAC override: an empty Mac_Name from the Ada side maps
   --  to the binding's "hmac-blake3" default before any FFI call.
   --  Mirrors every other binding's default-MAC override.
   function Resolved_Mac_Name (Mac_Name : String) return String is
   begin
      if Mac_Name = "" then
         return "hmac-blake3";
      else
         return Mac_Name;
      end if;
   end Resolved_Mac_Name;

   --  Wipes the cache buffer in place (zero out every byte) without
   --  releasing the heap allocation. Used before grow + on Close /
   --  Finalize so the most recent ciphertext / plaintext does not
   --  linger in heap memory.
   procedure Wipe_Cache (Self : in out Encryptor) is
   begin
      if Self.Cache /= null then
         for I in Self.Cache'Range loop
            Self.Cache (I) := 0;
         end loop;
      end if;
   end Wipe_Cache;

   --  Grows the cache buffer to at least Need bytes. Wipes the
   --  previous buffer (if any) before deallocating it so a previous-
   --  call ciphertext / plaintext does not linger in heap garbage
   --  between cipher calls.
   procedure Ensure_Capacity
     (Self : in out Encryptor;
      Need : Stream_Element_Offset)
   is
   begin
      if Self.Cache /= null and then Self.Cache'Length >= Need then
         return;
      end if;
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
      Self.Cache := new Byte_Array (1 .. Need);
   end Ensure_Capacity;

   --  C-convention access type for the four ITB_Easy_{Encrypt,Decrypt,
   --  EncryptAuth,DecryptAuth} entry points. Identical signature
   --  across all four; only the function pointer differs.
   type Easy_Cipher_Fn is access function
     (H       : Itb.Sys.Handle;
      In_Buf  : System.Address;
      In_Len  : Interfaces.C.size_t;
      Out_Buf : System.Address;
      Out_Cap : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t) return Interfaces.C.int
   with Convention => C;

   --  Direct-call buffer-convention dispatcher with a per-encryptor
   --  output cache. Skips the size-probe round-trip the lower-level
   --  FFI helpers use: pre-allocates output capacity from a 1.25x
   --  upper bound (the empirical ITB ciphertext-expansion factor
   --  measured at <= 1.155 across every primitive / mode / nonce /
   --  payload-size combination) and falls through to an explicit
   --  grow-and-retry only on the rare under-shoot. Reuses the cache
   --  across calls.
   function Cipher_Call
     (Self    : in out Encryptor;
      Fn      : Easy_Cipher_Fn;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      Payload_Len : constant Stream_Element_Offset := Payload'Length;
      In_Addr     : constant System.Address :=
        (if Payload_Len > 0 then Payload'Address else System.Null_Address);

      --  1.25x + 4 KiB headroom comfortably exceeds the 1.155 max
      --  expansion factor observed across the primitive / mode /
      --  nonce-bits matrix; floor at 4 KiB so the very-small payload
      --  case still gets a usable buffer. The explicit Long_Long_Integer
      --  intermediate guards against Stream_Element_Offset overflow at
      --  very large payload sizes — under wrap the grow-and-retry path
      --  would still recover, but the saturated initial allocation
      --  avoids the extra round-trip.
      Cap_LL : constant Long_Long_Integer :=
        Long_Long_Integer'Max
          (4096,
           Long_Long_Integer (Payload_Len) * 5 / 4 + 4096);
      Cap     : constant Stream_Element_Offset :=
        Stream_Element_Offset (Cap_LL);
      Pt_Len_C : constant size_t := size_t (Payload_Len);
      Out_Len  : aliased size_t := 0;
      Status   : int;
   begin
      Ensure_Capacity (Self, Cap);

      Status := Fn
                  (H       => Self.Handle,
                   In_Buf  => In_Addr,
                   In_Len  => Pt_Len_C,
                   Out_Buf => Self.Cache.all'Address,
                   Out_Cap => size_t (Self.Cache.all'Length),
                   Out_Len => Out_Len'Access);

      if Status = Itb.Status.Buffer_Too_Small then
         --  Pre-allocation was too tight (extremely rare given the
         --  1.25x safety margin) — grow exactly to the required size
         --  and retry. The first call already paid for the underlying
         --  crypto via the current C ABI's full-encrypt-on-every-call
         --  contract, so the retry runs the work again; this is
         --  strictly the fallback path and not the hot loop.
         Ensure_Capacity (Self, Stream_Element_Offset (Out_Len));
         Status := Fn
                     (H       => Self.Handle,
                      In_Buf  => In_Addr,
                      In_Len  => Pt_Len_C,
                      Out_Buf => Self.Cache.all'Address,
                      Out_Cap => size_t (Self.Cache.all'Length),
                      Out_Len => Out_Len'Access);
      end if;

      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      if Out_Len = 0 then
         return Empty;
      end if;
      return Self.Cache (1 .. Stream_Element_Offset (Out_Len));
   end Cipher_Call;

   --  Probe / allocate / write helper for the Easy-Mode string
   --  getters of shape
   --      int FFI (uintptr_t h, char* out, size_t cap, size_t* outLen)
   --  Routes every non-OK return code through the Easy-Mode error
   --  translation so the offending JSON field name is folded into the
   --  raised exception when the rc is Status.Easy_Mismatch.
   type Easy_String_Getter is access function
     (H       : Itb.Sys.Handle;
      Out_Buf : System.Address;
      Cap     : Interfaces.C.size_t;
      Out_Len : access Interfaces.C.size_t) return Interfaces.C.int
   with Convention => C;

   function Read_Easy_String
     (H : Itb.Sys.Handle; Get : Easy_String_Getter) return String
   is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Get
                  (H       => H,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return "";
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : aliased char_array (1 .. Probe) := [others => nul];
         Out_Len : aliased size_t := 0;
      begin
         Status := Get
                     (H       => H,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Out_Len = 0 then
            return "";
         end if;
         --  libitb returns C strings with a trailing NUL counted in
         --  Out_Len; strip it before handing back to Ada.
         declare
            N : constant size_t :=
              (if Out_Len > 0 then Out_Len - 1 else 0);
         begin
            if N = 0 then
               return "";
            end if;
            return To_Ada (Buf (1 .. N), Trim_Nul => False);
         end;
      end;
   end Read_Easy_String;

   ---------------------------------------------------------------------
   --  Constructors
   ---------------------------------------------------------------------

   function Make
     (Primitive : String;
      Key_Bits  : Integer;
      Mac_Name  : String    := "";
      Mode      : Mode_Type := 1) return Encryptor
   is
      use Interfaces.C;
      C_Prim : Strings.chars_ptr := To_C_String_Or_Null (Primitive);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      --  Mode_Type's Static_Predicate (1 | 3) catches literal mis-use
      --  at compile time, but the predicate is only enforced at run
      --  time when the project is built with -gnata (assertion checks
      --  enabled). Make is the entry point that decides what mode
      --  reaches libitb, so the runtime guard belongs here regardless
      --  of the build configuration.
      if Mode /= 1 and then Mode /= 3 then
         raise Constraint_Error
           with "Itb.Encryptor.Make: Mode must be 1 (Single) or 3 (Triple)";
      end if;

      Status := Itb.Sys.ITB_Easy_New
                  (Primitive  => C_Prim,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Mode       => int (Mode),
                   Out_Handle => Handle'Access);
      Free_If_Allocated (C_Prim);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Make;

   function Mixed_Single
     (Prim_N   : String;
      Prim_D   : String;
      Prim_S   : String;
      Prim_L   : String;
      Key_Bits : Integer;
      Mac_Name : String := "") return Encryptor
   is
      use Interfaces.C;
      C_N    : Strings.chars_ptr := Strings.New_String (Prim_N);
      C_D    : Strings.chars_ptr := Strings.New_String (Prim_D);
      C_S    : Strings.chars_ptr := Strings.New_String (Prim_S);
      C_L    : Strings.chars_ptr := To_C_String_Or_Null (Prim_L);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_NewMixed
                  (Prim_N     => C_N,
                   Prim_D     => C_D,
                   Prim_S     => C_S,
                   Prim_L     => C_L,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Out_Handle => Handle'Access);
      Strings.Free (C_N);
      Strings.Free (C_D);
      Strings.Free (C_S);
      Free_If_Allocated (C_L);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Mixed_Single;

   function Mixed_Triple
     (Prim_N   : String;
      Prim_D1  : String;
      Prim_D2  : String;
      Prim_D3  : String;
      Prim_S1  : String;
      Prim_S2  : String;
      Prim_S3  : String;
      Prim_L   : String;
      Key_Bits : Integer;
      Mac_Name : String := "") return Encryptor
   is
      use Interfaces.C;
      C_N    : Strings.chars_ptr := Strings.New_String (Prim_N);
      C_D1   : Strings.chars_ptr := Strings.New_String (Prim_D1);
      C_D2   : Strings.chars_ptr := Strings.New_String (Prim_D2);
      C_D3   : Strings.chars_ptr := Strings.New_String (Prim_D3);
      C_S1   : Strings.chars_ptr := Strings.New_String (Prim_S1);
      C_S2   : Strings.chars_ptr := Strings.New_String (Prim_S2);
      C_S3   : Strings.chars_ptr := Strings.New_String (Prim_S3);
      C_L    : Strings.chars_ptr := To_C_String_Or_Null (Prim_L);
      C_Mac  : Strings.chars_ptr :=
        Strings.New_String (Resolved_Mac_Name (Mac_Name));
      Handle : aliased Itb.Sys.Handle := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_NewMixed3
                  (Prim_N     => C_N,
                   Prim_D1    => C_D1,
                   Prim_D2    => C_D2,
                   Prim_D3    => C_D3,
                   Prim_S1    => C_S1,
                   Prim_S2    => C_S2,
                   Prim_S3    => C_S3,
                   Prim_L     => C_L,
                   Key_Bits   => int (Key_Bits),
                   Mac_Name   => C_Mac,
                   Out_Handle => Handle'Access);
      Strings.Free (C_N);
      Strings.Free (C_D1);
      Strings.Free (C_D2);
      Strings.Free (C_D3);
      Strings.Free (C_S1);
      Strings.Free (C_S2);
      Strings.Free (C_S3);
      Free_If_Allocated (C_L);
      Strings.Free (C_Mac);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return E : Encryptor do
         E.Handle := Handle;
         E.Cache  := null;
      end return;
   end Mixed_Triple;

   ---------------------------------------------------------------------
   --  Cipher entry points
   ---------------------------------------------------------------------

   function Encrypt
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_Encrypt'Access, Plaintext);
   end Encrypt;

   function Decrypt
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_Decrypt'Access, Ciphertext);
   end Decrypt;

   function Encrypt_Auth
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_EncryptAuth'Access, Plaintext);
   end Encrypt_Auth;

   function Decrypt_Auth
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Cipher_Call
        (Self, Itb.Sys.ITB_Easy_DecryptAuth'Access, Ciphertext);
   end Decrypt_Auth;

   ---------------------------------------------------------------------
   --  Per-instance configuration setters
   ---------------------------------------------------------------------

   procedure Set_Nonce_Bits (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetNonceBits (Self.Handle, int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Nonce_Bits;

   procedure Set_Barrier_Fill (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetBarrierFill (Self.Handle, int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Barrier_Fill;

   procedure Set_Bit_Soup (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetBitSoup (Self.Handle, int (Mode));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Bit_Soup;

   procedure Set_Lock_Soup (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetLockSoup (Self.Handle, int (Mode));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Soup;

   procedure Set_Lock_Seed (Self : Encryptor; Mode : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetLockSeed (Self.Handle, int (Mode));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Lock_Seed;

   procedure Set_Chunk_Size (Self : Encryptor; N : Integer) is
      use Interfaces.C;
      Status : constant int :=
        Itb.Sys.ITB_Easy_SetChunkSize (Self.Handle, int (N));
   begin
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Set_Chunk_Size;

   ---------------------------------------------------------------------
   --  Read-only accessors
   ---------------------------------------------------------------------

   function Primitive (Self : Encryptor) return String is
   begin
      return Read_Easy_String
        (Self.Handle, Itb.Sys.ITB_Easy_Primitive'Access);
   end Primitive;

   function Primitive_At (Self : Encryptor; Slot : Integer) return String is
      use Interfaces.C;
      H      : constant Itb.Sys.Handle := Self.Handle;
      Slot_C : constant int := int (Slot);
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_PrimitiveAt
                  (H       => H,
                   Slot    => Slot_C,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return "";
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : aliased char_array (1 .. Probe) := [others => nul];
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_PrimitiveAt
                     (H       => H,
                      Slot    => Slot_C,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         if Out_Len = 0 then
            return "";
         end if;
         declare
            N : constant size_t :=
              (if Out_Len > 0 then Out_Len - 1 else 0);
         begin
            if N = 0 then
               return "";
            end if;
            return To_Ada (Buf (1 .. N), Trim_Nul => False);
         end;
      end;
   end Primitive_At;

   function Key_Bits (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_KeyBits (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Key_Bits;

   function Mode (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_Mode (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Mode;

   function MAC_Name (Self : Encryptor) return String is
   begin
      return Read_Easy_String
        (Self.Handle, Itb.Sys.ITB_Easy_MACName'Access);
   end MAC_Name;

   function Seed_Count (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_SeedCount (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Seed_Count;

   function Has_PRF_Keys (Self : Encryptor) return Boolean is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_HasPRFKeys (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return V /= 0;
   end Has_PRF_Keys;

   function Is_Mixed (Self : Encryptor) return Boolean is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_IsMixed (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return V /= 0;
   end Is_Mixed;

   function Nonce_Bits (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_NonceBits (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Nonce_Bits;

   function Header_Size (Self : Encryptor) return Integer is
      use Interfaces.C;
      Out_Status : aliased int := 0;
      V          : constant int :=
        Itb.Sys.ITB_Easy_HeaderSize (Self.Handle, Out_Status'Access);
   begin
      if Out_Status /= 0 then
         Itb.Errors.Raise_For (Integer (Out_Status));
      end if;
      return Integer (V);
   end Header_Size;

   ---------------------------------------------------------------------
   --  Component / key extractors
   ---------------------------------------------------------------------

   function Get_Seed_Components
     (Self : Encryptor;
      Slot : Integer) return Component_Array
   is
      use Interfaces.C;
      Probe  : aliased int := 0;
      Status : int;
   begin
      --  Probe required count.
      Status := Itb.Sys.ITB_Easy_SeedComponents
                  (H       => Self.Handle,
                   Slot    => int (Slot),
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK then
         return Component_Array'(1 .. 0 => 0);
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         N       : constant Natural := Natural (Probe);
         Buf     : Component_Array (1 .. N);
         Out_Len : aliased int := 0;
      begin
         Status := Itb.Sys.ITB_Easy_SeedComponents
                     (H       => Self.Handle,
                      Slot    => int (Slot),
                      Out_Buf => Buf'Address,
                      Cap     => int (N),
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Natural (Out_Len));
      end;
   end Get_Seed_Components;

   function Get_PRF_Key
     (Self : Encryptor;
      Slot : Integer) return Byte_Array
   is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_PRFKey
                  (H       => Self.Handle,
                   Slot    => int (Slot),
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      --  Probe pattern: zero-length key (siphash24) -> OK with
      --  Probe = 0; non-zero length -> Buffer_Too_Small with Probe
      --  carrying the required size. Bad_Input is reserved for
      --  out-of-range slot or no-fixed-key primitive (raised below).
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_PRFKey
                     (H       => Self.Handle,
                      Slot    => int (Slot),
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Get_PRF_Key;

   function Get_MAC_Key (Self : Encryptor) return Byte_Array is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_MACKey
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Cap     => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_MACKey
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Cap     => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Get_MAC_Key;

   ---------------------------------------------------------------------
   --  Streaming helpers
   ---------------------------------------------------------------------

   function Parse_Chunk_Len
     (Self   : Encryptor;
      Header : Byte_Array) return Natural
   is
      use Interfaces.C;
      Hdr_Addr : constant System.Address :=
        (if Header'Length > 0 then Header'Address else System.Null_Address);
      Out_Chunk : aliased size_t := 0;
      Status    : int;
   begin
      Status := Itb.Sys.ITB_Easy_ParseChunkLen
                  (H          => Self.Handle,
                   Header     => Hdr_Addr,
                   Header_Len => Header'Length,
                   Out_Chunk  => Out_Chunk'Access);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
      return Natural (Out_Chunk);
   end Parse_Chunk_Len;

   ---------------------------------------------------------------------
   --  Lifecycle
   ---------------------------------------------------------------------

   procedure Close (Self : in out Encryptor) is
      use Interfaces.C;
      Status : int;
   begin
      if Self.Handle = 0 then
         return;
      end if;
      --  Wipe + free the cached output buffer before releasing the
      --  Go-side state so a previous-call ciphertext / plaintext does
      --  not linger in heap memory after the encryptor has been
      --  zeroed on the Go side.
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
      Status := Itb.Sys.ITB_Easy_Close (Self.Handle);
      --  Close is documented as idempotent on the Go side; any
      --  non-OK return after close is a bug.
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Close;

   ---------------------------------------------------------------------
   --  State persistence
   ---------------------------------------------------------------------

   function Export_State (Self : Encryptor) return Byte_Array is
      use Interfaces.C;
      Probe  : aliased size_t := 0;
      Status : int;
   begin
      Status := Itb.Sys.ITB_Easy_Export
                  (H       => Self.Handle,
                   Out_Buf => System.Null_Address,
                   Out_Cap => 0,
                   Out_Len => Probe'Access);
      if Status = Itb.Status.OK and then Probe = 0 then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Buf     : Byte_Array (1 .. Stream_Element_Offset (Probe));
         Out_Len : aliased size_t := 0;
      begin
         Status := Itb.Sys.ITB_Easy_Export
                     (H       => Self.Handle,
                      Out_Buf => Buf'Address,
                      Out_Cap => Probe,
                      Out_Len => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Buf (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Export_State;

   procedure Import_State
     (Self : in out Encryptor; Blob : Byte_Array)
   is
      use Interfaces.C;
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Status    : int;
   begin
      Status := Itb.Sys.ITB_Easy_Import
                  (H        => Self.Handle,
                   Blob     => Blob_Addr,
                   Blob_Len => Blob'Length);
      if Status /= 0 then
         Itb.Errors.Raise_For (Integer (Status));
      end if;
   end Import_State;

   function Peek_Config (Blob : Byte_Array) return Peeked_Config is
      use Interfaces.C;
      Blob_Addr : constant System.Address :=
        (if Blob'Length > 0 then Blob'Address else System.Null_Address);
      Prim_Probe : aliased size_t := 0;
      Mac_Probe  : aliased size_t := 0;
      KB_Out     : aliased int := 0;
      Mode_Out   : aliased int := 0;
      Status     : int;
   begin
      --  Probe both string sizes first.
      Status := Itb.Sys.ITB_Easy_PeekConfig
                  (Blob       => Blob_Addr,
                   Blob_Len   => Blob'Length,
                   Prim_Out   => System.Null_Address,
                   Prim_Cap   => 0,
                   Prim_Len   => Prim_Probe'Access,
                   Key_Bits   => KB_Out'Access,
                   Mode_Out   => Mode_Out'Access,
                   Mac_Out    => System.Null_Address,
                   Mac_Cap    => 0,
                   Mac_Len    => Mac_Probe'Access);
      if Status /= Itb.Status.OK and then Status /= Itb.Status.Buffer_Too_Small
      then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Prim_Buf : aliased char_array (1 .. Prim_Probe) := [others => nul];
         Mac_Buf  : aliased char_array (1 .. Mac_Probe)  := [others => nul];
         Prim_Len : aliased size_t := 0;
         Mac_Len  : aliased size_t := 0;
         Result   : Peeked_Config;
      begin
         Status := Itb.Sys.ITB_Easy_PeekConfig
                     (Blob       => Blob_Addr,
                      Blob_Len   => Blob'Length,
                      Prim_Out   => Prim_Buf'Address,
                      Prim_Cap   => Prim_Probe,
                      Prim_Len   => Prim_Len'Access,
                      Key_Bits   => KB_Out'Access,
                      Mode_Out   => Mode_Out'Access,
                      Mac_Out    => Mac_Buf'Address,
                      Mac_Cap    => Mac_Probe,
                      Mac_Len    => Mac_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;

         declare
            Prim_N : constant size_t :=
              (if Prim_Len > 0 then Prim_Len - 1 else 0);
            Mac_N  : constant size_t :=
              (if Mac_Len > 0 then Mac_Len - 1 else 0);
         begin
            if Prim_N > 0 then
               Result.Primitive :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   (To_Ada (Prim_Buf (1 .. Prim_N), Trim_Nul => False));
            end if;
            if Mac_N > 0 then
               Result.MAC_Name :=
                 Ada.Strings.Unbounded.To_Unbounded_String
                   (To_Ada (Mac_Buf (1 .. Mac_N), Trim_Nul => False));
            end if;
         end;
         Result.Key_Bits := Integer (KB_Out);
         Result.Mode     := Integer (Mode_Out);
         return Result;
      end;
   end Peek_Config;

   ---------------------------------------------------------------------
   --  Finalize — deterministic release at scope exit.
   ---------------------------------------------------------------------

   overriding procedure Finalize (Self : in out Encryptor) is
      use Interfaces.C;
      Discard : int;
      pragma Unreferenced (Discard);
   begin
      if Self.Handle /= 0 then
         Discard := Itb.Sys.ITB_Easy_Free (Self.Handle);
         Self.Handle := 0;
      end if;
      if Self.Cache /= null then
         Wipe_Cache (Self);
         Free_Cache (Self.Cache);
      end if;
   end Finalize;

end Itb.Encryptor;
