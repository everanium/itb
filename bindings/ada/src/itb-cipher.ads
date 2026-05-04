--  Itb.Cipher — low-level encrypt / decrypt entry points.
--
--  Mirrors bindings/rust/src/encrypt.rs. Provides eight free
--  subprograms over libitb's low-level cipher surface:
--
--    Encrypt              Single Ouroboros, 3-seed.
--    Decrypt              Inverse.
--    Encrypt_Triple       Triple Ouroboros, 7-seed.
--    Decrypt_Triple       Inverse.
--    Encrypt_Auth         Authenticated Single (3 seeds + MAC).
--    Decrypt_Auth         Inverse; raises Itb_Error / MAC_Failure
--                         on tampered ciphertext or wrong MAC key.
--    Encrypt_Auth_Triple  Authenticated Triple (7 seeds + MAC).
--    Decrypt_Auth_Triple  Inverse.
--
--  All seeds passed to one cipher call must share the same native
--  hash width; mixing widths surfaces as Itb_Error with Status_Code
--  = Seed_Width_Mix.

with Itb.MAC;
with Itb.Seed;

package Itb.Cipher is
   pragma Preelaborate;

   ---------------------------------------------------------------------
   --  Single Ouroboros (3 seeds)
   ---------------------------------------------------------------------

   function Encrypt
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array;

   function Decrypt
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Triple Ouroboros (7 seeds)
   ---------------------------------------------------------------------

   function Encrypt_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array;

   function Decrypt_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Authenticated Single (3 seeds + MAC)
   ---------------------------------------------------------------------

   function Encrypt_Auth
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array;

   function Decrypt_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Authenticated Triple (7 seeds + MAC)
   ---------------------------------------------------------------------

   function Encrypt_Auth_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array;

   function Decrypt_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array;

end Itb.Cipher;
