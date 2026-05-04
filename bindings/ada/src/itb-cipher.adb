--  Itb.Cipher body — probe / allocate / write idiom over libitb's
--  ITB_Encrypt* / ITB_Decrypt* family.

with Ada.Streams; use Ada.Streams;
with Interfaces.C;
with System;

with Itb.Errors;
with Itb.Status;
with Itb.Sys;

package body Itb.Cipher is

   ---------------------------------------------------------------------
   --  Internal helpers
   ---------------------------------------------------------------------

   function Empty return Byte_Array is
   begin
      return Byte_Array'(1 .. 0 => 0);
   end Empty;

   --  Single Ouroboros (Encrypt / Decrypt) — shared probe / allocate
   --  / write idiom. The fn-pointer choice (Encrypt vs Decrypt) is
   --  passed by the caller; both signatures are identical.
   type Single_Cipher_Fn is access function
     (Noise_Handle : Itb.Sys.Handle;
      Data_Handle  : Itb.Sys.Handle;
      Start_Handle : Itb.Sys.Handle;
      Plaintext    : System.Address;
      Pt_Len       : Interfaces.C.size_t;
      Out_Buf      : System.Address;
      Out_Cap      : Interfaces.C.size_t;
      Out_Len      : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Single
     (Fn      : Single_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data    : Itb.Seed.Seed;
      Start   : Itb.Seed.Seed;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      --  Probe required output size.
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data),
                    Itb.Seed.Raw_Handle (Start),
                    In_Addr,
                    Payload'Length,
                    System.Null_Address,
                    0,
                    Probe'Access);
      if Status = Itb.Status.OK then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Need    : constant size_t := Probe;
         Result  : Byte_Array (1 .. Stream_Element_Offset (Need));
         Out_Len : aliased size_t := 0;
      begin
         Status := Fn (Itb.Seed.Raw_Handle (Noise),
                       Itb.Seed.Raw_Handle (Data),
                       Itb.Seed.Raw_Handle (Start),
                       In_Addr,
                       Payload'Length,
                       Result'Address,
                       Need,
                       Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Run_Single;

   type Triple_Cipher_Fn is access function
     (Noise_Handle  : Itb.Sys.Handle;
      Data_Handle1  : Itb.Sys.Handle;
      Data_Handle2  : Itb.Sys.Handle;
      Data_Handle3  : Itb.Sys.Handle;
      Start_Handle1 : Itb.Sys.Handle;
      Start_Handle2 : Itb.Sys.Handle;
      Start_Handle3 : Itb.Sys.Handle;
      Plaintext     : System.Address;
      Pt_Len        : Interfaces.C.size_t;
      Out_Buf       : System.Address;
      Out_Cap       : Interfaces.C.size_t;
      Out_Len       : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Triple
     (Fn      : Triple_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data1   : Itb.Seed.Seed;
      Data2   : Itb.Seed.Seed;
      Data3   : Itb.Seed.Seed;
      Start1  : Itb.Seed.Seed;
      Start2  : Itb.Seed.Seed;
      Start3  : Itb.Seed.Seed;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data1),
                    Itb.Seed.Raw_Handle (Data2),
                    Itb.Seed.Raw_Handle (Data3),
                    Itb.Seed.Raw_Handle (Start1),
                    Itb.Seed.Raw_Handle (Start2),
                    Itb.Seed.Raw_Handle (Start3),
                    In_Addr,
                    Payload'Length,
                    System.Null_Address,
                    0,
                    Probe'Access);
      if Status = Itb.Status.OK then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Need    : constant size_t := Probe;
         Result  : Byte_Array (1 .. Stream_Element_Offset (Need));
         Out_Len : aliased size_t := 0;
      begin
         Status := Fn (Itb.Seed.Raw_Handle (Noise),
                       Itb.Seed.Raw_Handle (Data1),
                       Itb.Seed.Raw_Handle (Data2),
                       Itb.Seed.Raw_Handle (Data3),
                       Itb.Seed.Raw_Handle (Start1),
                       Itb.Seed.Raw_Handle (Start2),
                       Itb.Seed.Raw_Handle (Start3),
                       In_Addr,
                       Payload'Length,
                       Result'Address,
                       Need,
                       Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Run_Triple;

   type Auth_Cipher_Fn is access function
     (Noise_Handle : Itb.Sys.Handle;
      Data_Handle  : Itb.Sys.Handle;
      Start_Handle : Itb.Sys.Handle;
      MAC_Handle   : Itb.Sys.Handle;
      Plaintext    : System.Address;
      Pt_Len       : Interfaces.C.size_t;
      Out_Buf      : System.Address;
      Out_Cap      : Interfaces.C.size_t;
      Out_Len      : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Auth
     (Fn      : Auth_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data    : Itb.Seed.Seed;
      Start   : Itb.Seed.Seed;
      Mac     : Itb.MAC.MAC;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data),
                    Itb.Seed.Raw_Handle (Start),
                    Itb.MAC.Raw_Handle (Mac),
                    In_Addr,
                    Payload'Length,
                    System.Null_Address,
                    0,
                    Probe'Access);
      if Status = Itb.Status.OK then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Need    : constant size_t := Probe;
         Result  : Byte_Array (1 .. Stream_Element_Offset (Need));
         Out_Len : aliased size_t := 0;
      begin
         Status := Fn (Itb.Seed.Raw_Handle (Noise),
                       Itb.Seed.Raw_Handle (Data),
                       Itb.Seed.Raw_Handle (Start),
                       Itb.MAC.Raw_Handle (Mac),
                       In_Addr,
                       Payload'Length,
                       Result'Address,
                       Need,
                       Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Run_Auth;

   type Auth_Triple_Cipher_Fn is access function
     (Noise_Handle  : Itb.Sys.Handle;
      Data_Handle1  : Itb.Sys.Handle;
      Data_Handle2  : Itb.Sys.Handle;
      Data_Handle3  : Itb.Sys.Handle;
      Start_Handle1 : Itb.Sys.Handle;
      Start_Handle2 : Itb.Sys.Handle;
      Start_Handle3 : Itb.Sys.Handle;
      MAC_Handle    : Itb.Sys.Handle;
      Plaintext     : System.Address;
      Pt_Len        : Interfaces.C.size_t;
      Out_Buf       : System.Address;
      Out_Cap       : Interfaces.C.size_t;
      Out_Len       : access Interfaces.C.size_t)
      return Interfaces.C.int
   with Convention => C;

   function Run_Auth_Triple
     (Fn      : Auth_Triple_Cipher_Fn;
      Noise   : Itb.Seed.Seed;
      Data1   : Itb.Seed.Seed;
      Data2   : Itb.Seed.Seed;
      Data3   : Itb.Seed.Seed;
      Start1  : Itb.Seed.Seed;
      Start2  : Itb.Seed.Seed;
      Start3  : Itb.Seed.Seed;
      Mac     : Itb.MAC.MAC;
      Payload : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Payload'Length > 0 then Payload'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Fn (Itb.Seed.Raw_Handle (Noise),
                    Itb.Seed.Raw_Handle (Data1),
                    Itb.Seed.Raw_Handle (Data2),
                    Itb.Seed.Raw_Handle (Data3),
                    Itb.Seed.Raw_Handle (Start1),
                    Itb.Seed.Raw_Handle (Start2),
                    Itb.Seed.Raw_Handle (Start3),
                    Itb.MAC.Raw_Handle (Mac),
                    In_Addr,
                    Payload'Length,
                    System.Null_Address,
                    0,
                    Probe'Access);
      if Status = Itb.Status.OK then
         return Empty;
      end if;
      if Status /= Itb.Status.Buffer_Too_Small then
         Itb.Errors.Raise_For (Integer (Status));
      end if;

      declare
         Need    : constant size_t := Probe;
         Result  : Byte_Array (1 .. Stream_Element_Offset (Need));
         Out_Len : aliased size_t := 0;
      begin
         Status := Fn (Itb.Seed.Raw_Handle (Noise),
                       Itb.Seed.Raw_Handle (Data1),
                       Itb.Seed.Raw_Handle (Data2),
                       Itb.Seed.Raw_Handle (Data3),
                       Itb.Seed.Raw_Handle (Start1),
                       Itb.Seed.Raw_Handle (Start2),
                       Itb.Seed.Raw_Handle (Start3),
                       Itb.MAC.Raw_Handle (Mac),
                       In_Addr,
                       Payload'Length,
                       Result'Address,
                       Need,
                       Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Run_Auth_Triple;

   ---------------------------------------------------------------------
   --  Public API — thin shells around the helpers.
   ---------------------------------------------------------------------

   function Encrypt
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Single
        (Itb.Sys.ITB_Encrypt'Access, Noise, Data, Start, Plaintext);
   end Encrypt;

   function Decrypt
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Single
        (Itb.Sys.ITB_Decrypt'Access, Noise, Data, Start, Ciphertext);
   end Decrypt;

   function Encrypt_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Triple
        (Itb.Sys.ITB_Encrypt3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Plaintext);
   end Encrypt_Triple;

   function Decrypt_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Triple
        (Itb.Sys.ITB_Decrypt3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Ciphertext);
   end Decrypt_Triple;

   function Encrypt_Auth
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth
        (Itb.Sys.ITB_EncryptAuth'Access,
         Noise, Data, Start, Mac, Plaintext);
   end Encrypt_Auth;

   function Decrypt_Auth
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth
        (Itb.Sys.ITB_DecryptAuth'Access,
         Noise, Data, Start, Mac, Ciphertext);
   end Decrypt_Auth;

   function Encrypt_Auth_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Mac       : Itb.MAC.MAC;
      Plaintext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth_Triple
        (Itb.Sys.ITB_EncryptAuth3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Mac, Plaintext);
   end Encrypt_Auth_Triple;

   function Decrypt_Auth_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Mac        : Itb.MAC.MAC;
      Ciphertext : Byte_Array) return Byte_Array is
   begin
      return Run_Auth_Triple
        (Itb.Sys.ITB_DecryptAuth3'Access,
         Noise, Data1, Data2, Data3, Start1, Start2, Start3, Mac, Ciphertext);
   end Decrypt_Auth_Triple;

end Itb.Cipher;
