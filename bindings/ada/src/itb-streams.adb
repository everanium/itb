--  Itb.Streams body — chunked encrypt / decrypt over
--  Ada.Streams.Root_Stream_Type'Class.

with Ada.Streams; use Ada.Streams;
with Ada.Unchecked_Deallocation;
with Interfaces.C;
with System;

with Itb.Errors;
with Itb.Status;

package body Itb.Streams is

   ---------------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------------

   procedure Free_Buffer is new Ada.Unchecked_Deallocation
     (Object => Byte_Array, Name => Byte_Buffer_Access);

   --  Allocates a fresh Byte_Array of the given Length on the heap.
   function Allocate (Length : Stream_Element_Offset)
     return Byte_Buffer_Access
   is
      Result : constant Byte_Buffer_Access :=
        new Byte_Array (1 .. Length);
   begin
      for I in Result'Range loop
         Result (I) := 0;
      end loop;
      return Result;
   end Allocate;

   --  Writes Data to the underlying Ada.Streams sink. Wraps the
   --  Stream'Class.Write primitive so call sites stay readable.
   procedure Write_All
     (Sink : not null access Root_Stream_Type'Class;
      Data : Byte_Array) is
   begin
      if Data'Length > 0 then
         Sink.all.Write (Data);
      end if;
   end Write_All;

   ---------------------------------------------------------------------
   --  Single Ouroboros — encryptor.
   ---------------------------------------------------------------------

   function Make
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor do
         E.Noise_H    := Itb.Seed.Raw_Handle (Noise);
         E.Data_H     := Itb.Seed.Raw_Handle (Data);
         E.Start_H    := Itb.Seed.Raw_Handle (Start);
         E.Sink       := Sink;
         E.Chunk_Size := Chunk_Size;
         E.Buf        := Allocate (Chunk_Size);
         E.Buf_Used   := 0;
         E.Closed     := False;
      end return;
   end Make;

   ---------------------------------------------------------------------
   --  Inline encrypt / decrypt helpers — talk directly to libitb so we
   --  don't need to materialise an Itb.Seed.Seed value for each call.
   --  Mirrors Itb.Cipher.Run_*'s two-call probe / allocate / write
   --  idiom but consumes raw Itb.Sys.Handle values, which is what the
   --  streaming wrappers carry.
   ---------------------------------------------------------------------

   function Empty return Byte_Array is
   begin
      return Byte_Array'(1 .. 0 => 0);
   end Empty;

   function Encrypt_Single
     (Noise_H : Itb.Sys.Handle;
      Data_H  : Itb.Sys.Handle;
      Start_H : Itb.Sys.Handle;
      Plain   : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Encrypt
                  (Noise_Handle => Noise_H,
                   Data_Handle  => Data_H,
                   Start_Handle => Start_H,
                   Plaintext    => In_Addr,
                   Pt_Len       => Plain'Length,
                   Out_Buf      => System.Null_Address,
                   Out_Cap      => 0,
                   Out_Len      => Probe'Access);
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
         Status := Itb.Sys.ITB_Encrypt
                     (Noise_Handle => Noise_H,
                      Data_Handle  => Data_H,
                      Start_Handle => Start_H,
                      Plaintext    => In_Addr,
                      Pt_Len       => Plain'Length,
                      Out_Buf      => Result'Address,
                      Out_Cap      => Need,
                      Out_Len      => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Encrypt_Single;

   function Decrypt_Single
     (Noise_H : Itb.Sys.Handle;
      Data_H  : Itb.Sys.Handle;
      Start_H : Itb.Sys.Handle;
      Cipher  : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Decrypt
                  (Noise_Handle => Noise_H,
                   Data_Handle  => Data_H,
                   Start_Handle => Start_H,
                   Ciphertext   => In_Addr,
                   Ct_Len       => Cipher'Length,
                   Out_Buf      => System.Null_Address,
                   Out_Cap      => 0,
                   Out_Len      => Probe'Access);
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
         Status := Itb.Sys.ITB_Decrypt
                     (Noise_Handle => Noise_H,
                      Data_Handle  => Data_H,
                      Start_Handle => Start_H,
                      Ciphertext   => In_Addr,
                      Ct_Len       => Cipher'Length,
                      Out_Buf      => Result'Address,
                      Out_Cap      => Need,
                      Out_Len      => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Decrypt_Single;

   function Encrypt_Triple_Inline
     (Noise_H  : Itb.Sys.Handle;
      Data1_H  : Itb.Sys.Handle;
      Data2_H  : Itb.Sys.Handle;
      Data3_H  : Itb.Sys.Handle;
      Start1_H : Itb.Sys.Handle;
      Start2_H : Itb.Sys.Handle;
      Start3_H : Itb.Sys.Handle;
      Plain    : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Plain'Length > 0 then Plain'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Encrypt3
                  (Noise_Handle  => Noise_H,
                   Data_Handle1  => Data1_H,
                   Data_Handle2  => Data2_H,
                   Data_Handle3  => Data3_H,
                   Start_Handle1 => Start1_H,
                   Start_Handle2 => Start2_H,
                   Start_Handle3 => Start3_H,
                   Plaintext     => In_Addr,
                   Pt_Len        => Plain'Length,
                   Out_Buf       => System.Null_Address,
                   Out_Cap       => 0,
                   Out_Len       => Probe'Access);
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
         Status := Itb.Sys.ITB_Encrypt3
                     (Noise_Handle  => Noise_H,
                      Data_Handle1  => Data1_H,
                      Data_Handle2  => Data2_H,
                      Data_Handle3  => Data3_H,
                      Start_Handle1 => Start1_H,
                      Start_Handle2 => Start2_H,
                      Start_Handle3 => Start3_H,
                      Plaintext     => In_Addr,
                      Pt_Len        => Plain'Length,
                      Out_Buf       => Result'Address,
                      Out_Cap       => Need,
                      Out_Len       => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Encrypt_Triple_Inline;

   function Decrypt_Triple_Inline
     (Noise_H  : Itb.Sys.Handle;
      Data1_H  : Itb.Sys.Handle;
      Data2_H  : Itb.Sys.Handle;
      Data3_H  : Itb.Sys.Handle;
      Start1_H : Itb.Sys.Handle;
      Start2_H : Itb.Sys.Handle;
      Start3_H : Itb.Sys.Handle;
      Cipher   : Byte_Array) return Byte_Array
   is
      use Interfaces.C;
      In_Addr : constant System.Address :=
        (if Cipher'Length > 0 then Cipher'Address else System.Null_Address);
      Probe   : aliased size_t := 0;
      Status  : int;
   begin
      Status := Itb.Sys.ITB_Decrypt3
                  (Noise_Handle  => Noise_H,
                   Data_Handle1  => Data1_H,
                   Data_Handle2  => Data2_H,
                   Data_Handle3  => Data3_H,
                   Start_Handle1 => Start1_H,
                   Start_Handle2 => Start2_H,
                   Start_Handle3 => Start3_H,
                   Ciphertext    => In_Addr,
                   Ct_Len        => Cipher'Length,
                   Out_Buf       => System.Null_Address,
                   Out_Cap       => 0,
                   Out_Len       => Probe'Access);
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
         Status := Itb.Sys.ITB_Decrypt3
                     (Noise_Handle  => Noise_H,
                      Data_Handle1  => Data1_H,
                      Data_Handle2  => Data2_H,
                      Data_Handle3  => Data3_H,
                      Start_Handle1 => Start1_H,
                      Start_Handle2 => Start2_H,
                      Start_Handle3 => Start3_H,
                      Ciphertext    => In_Addr,
                      Ct_Len        => Cipher'Length,
                      Out_Buf       => Result'Address,
                      Out_Cap       => Need,
                      Out_Len       => Out_Len'Access);
         if Status /= 0 then
            Itb.Errors.Raise_For (Integer (Status));
         end if;
         return Result (1 .. Stream_Element_Offset (Out_Len));
      end;
   end Decrypt_Triple_Inline;

   ---------------------------------------------------------------------
   --  Stream_Encryptor — Write_Plaintext / Finish.
   ---------------------------------------------------------------------

   procedure Drain_Single (Self : in out Stream_Encryptor) is
   begin
      while Self.Buf_Used >= Self.Chunk_Size loop
         declare
            CT : constant Byte_Array :=
              Encrypt_Single
                (Self.Noise_H, Self.Data_H, Self.Start_H,
                 Self.Buf (1 .. Self.Chunk_Size));
         begin
            Write_All (Self.Sink, CT);
            if Self.Buf_Used > Self.Chunk_Size then
               Self.Buf (1 .. Self.Buf_Used - Self.Chunk_Size) :=
                 Self.Buf
                   (Self.Chunk_Size + 1 .. Self.Buf_Used);
            end if;
            Self.Buf_Used := Self.Buf_Used - Self.Chunk_Size;
         end;
      end loop;
   end Drain_Single;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            if Self.Buf_Used >= Self.Chunk_Size then
               Drain_Single (Self);
            end if;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         declare
            CT : constant Byte_Array :=
              Encrypt_Single
                (Self.Noise_H, Self.Data_H, Self.Start_H,
                 Self.Buf (1 .. Self.Buf_Used));
         begin
            Write_All (Self.Sink, CT);
            Self.Buf_Used := 0;
         end;
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Encryptor) is
   begin
      --  Best-effort flush; errors during finalization are swallowed
      --  because there is no path to surface them. Callers that need
      --  to see flush-time errors must call Finish explicitly.
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor — Read_Plaintext / Finish.
   ---------------------------------------------------------------------

   --  Initial read-buffer capacity for the decryptor's ciphertext
   --  staging buffer. Grows on demand if a single chunk turns out
   --  to be larger.
   Default_CT_Buffer : constant Stream_Element_Offset := 64 * 1024;

   --  Grows Self.Buf so that at least Min_Cap bytes fit.
   procedure Grow_Buf
     (Self    : in out Stream_Decryptor;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Buf;

   --  Reads up to Self.Buf'Length - Self.Buf_Used bytes from Source
   --  into the tail of Self.Buf. Sets Self.At_EOF on EOF. Returns the
   --  number of bytes actually read (0 on EOF).
   procedure Pull_Source
     (Self  : in out Stream_Decryptor;
      Read  : out Stream_Element_Offset)
   is
      First : constant Stream_Element_Offset := Self.Buf_Used + 1;
      Last  : constant Stream_Element_Offset := Self.Buf'Length;
      Got   : Stream_Element_Offset := First - 1;
   begin
      if First > Last then
         Read := 0;
         return;
      end if;
      Self.Source.all.Read
        (Self.Buf (First .. Last), Got);
      if Got < First then
         Self.At_EOF := True;
         Read        := 0;
      else
         Read          := Got - First + 1;
         Self.Buf_Used := Got;
      end if;
   end Pull_Source;

   function Make
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor is
   begin
      return D : Stream_Decryptor do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data_H      := Itb.Seed.Raw_Handle (Data);
         D.Start_H     := Itb.Seed.Raw_Handle (Start);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Header_Size := Stream_Element_Offset (Itb.Header_Size);
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make;

   --  Tries to decrypt one full chunk from Self.Buf; returns True if a
   --  chunk was decoded into Self.Plain (Plain_Pos / Plain_Last reset).
   --  Returns False when more ciphertext is required from Source. May
   --  raise on a malformed chunk header.
   function Try_Decode_Chunk
     (Self : in out Stream_Decryptor) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
   begin
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Buf (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      declare
         PT : constant Byte_Array :=
           Decrypt_Single
             (Self.Noise_H, Self.Data_H, Self.Start_H,
              Self.Buf (1 .. Stream_Element_Offset (Want)));
         Tail : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         --  Slide unconsumed ciphertext bytes down.
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         --  Stash the recovered plaintext for the caller to drain.
         if Self.Plain /= null then
            Free_Buffer (Self.Plain);
         end if;
         if PT'Length > 0 then
            Self.Plain := new Byte_Array'(PT);
         else
            Self.Plain := new Byte_Array (1 .. 0);
         end if;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         return True;
      end;
   end Try_Decode_Chunk;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         --  Drain anything already decoded.
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            --  Either no chunk decoded yet, or the previous one is
            --  drained — try to decode a new one.
            if not Try_Decode_Chunk (Self) then
               --  Need more ciphertext from the underlying source.
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     --  Full buffer but Try_Decode said no — header
                     --  reports a chunk larger than current capacity;
                     --  enlarge.
                     Grow_Buf (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor) is
   begin
      if Self.Closed then
         return;
      end if;
      --  Drain any remaining decoded plaintext silently — Finish only
      --  validates ciphertext-side framing.
      if Self.Buf_Used > 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Decryptor) is
   begin
      --  Mark closed without raising on partial input — Finalize has
      --  no path to surface errors. Callers who need to detect a
      --  half-chunk tail must call Finish explicitly.
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Free_Buffer (Self.Plain);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Encryptor_Triple — same shape, 7 seed handles.
   ---------------------------------------------------------------------

   function Make_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
      return Stream_Encryptor_Triple is
   begin
      if Chunk_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      return E : Stream_Encryptor_Triple do
         E.Noise_H    := Itb.Seed.Raw_Handle (Noise);
         E.Data1_H    := Itb.Seed.Raw_Handle (Data1);
         E.Data2_H    := Itb.Seed.Raw_Handle (Data2);
         E.Data3_H    := Itb.Seed.Raw_Handle (Data3);
         E.Start1_H   := Itb.Seed.Raw_Handle (Start1);
         E.Start2_H   := Itb.Seed.Raw_Handle (Start2);
         E.Start3_H   := Itb.Seed.Raw_Handle (Start3);
         E.Sink       := Sink;
         E.Chunk_Size := Chunk_Size;
         E.Buf        := Allocate (Chunk_Size);
         E.Buf_Used   := 0;
         E.Closed     := False;
      end return;
   end Make_Triple;

   procedure Drain_Triple (Self : in out Stream_Encryptor_Triple) is
   begin
      while Self.Buf_Used >= Self.Chunk_Size loop
         declare
            CT : constant Byte_Array :=
              Encrypt_Triple_Inline
                (Self.Noise_H,
                 Self.Data1_H, Self.Data2_H, Self.Data3_H,
                 Self.Start1_H, Self.Start2_H, Self.Start3_H,
                 Self.Buf (1 .. Self.Chunk_Size));
         begin
            Write_All (Self.Sink, CT);
            if Self.Buf_Used > Self.Chunk_Size then
               Self.Buf (1 .. Self.Buf_Used - Self.Chunk_Size) :=
                 Self.Buf
                   (Self.Chunk_Size + 1 .. Self.Buf_Used);
            end if;
            Self.Buf_Used := Self.Buf_Used - Self.Chunk_Size;
         end;
      end loop;
   end Drain_Triple;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Triple;
      Data : Byte_Array)
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Data'Last loop
         declare
            Room      : constant Stream_Element_Offset :=
              Self.Buf'Length - Self.Buf_Used;
            Available : constant Stream_Element_Offset :=
              Data'Last - Cursor + 1;
            Take      : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min (Room, Available);
         begin
            if Take > 0 then
               Self.Buf
                 (Self.Buf_Used + 1 .. Self.Buf_Used + Take) :=
                 Data (Cursor .. Cursor + Take - 1);
               Self.Buf_Used := Self.Buf_Used + Take;
               Cursor        := Cursor + Take;
            end if;
            if Self.Buf_Used >= Self.Chunk_Size then
               Drain_Triple (Self);
            end if;
         end;
      end loop;
   end Write_Plaintext;

   procedure Finish (Self : in out Stream_Encryptor_Triple) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         declare
            CT : constant Byte_Array :=
              Encrypt_Triple_Inline
                (Self.Noise_H,
                 Self.Data1_H, Self.Data2_H, Self.Data3_H,
                 Self.Start1_H, Self.Start2_H, Self.Start3_H,
                 Self.Buf (1 .. Self.Buf_Used));
         begin
            Write_All (Self.Sink, CT);
            Self.Buf_Used := 0;
         end;
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Triple) is
   begin
      if not Self.Closed then
         begin
            Finish (Self);
         exception
            when others => null;
         end;
      end if;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Stream_Decryptor_Triple — same shape, 7 seed handles.
   ---------------------------------------------------------------------

   procedure Grow_Buf
     (Self    : in out Stream_Decryptor_Triple;
      Min_Cap : Stream_Element_Offset)
   is
      Old_Buf : Byte_Buffer_Access := Self.Buf;
      New_Cap : Stream_Element_Offset := Self.Buf'Length;
   begin
      while New_Cap < Min_Cap loop
         New_Cap := New_Cap * 2;
      end loop;
      declare
         New_Buf : constant Byte_Buffer_Access := Allocate (New_Cap);
      begin
         if Self.Buf_Used > 0 then
            New_Buf (1 .. Self.Buf_Used) :=
              Old_Buf (1 .. Self.Buf_Used);
         end if;
         Self.Buf := New_Buf;
      end;
      Free_Buffer (Old_Buf);
   end Grow_Buf;

   procedure Pull_Source
     (Self  : in out Stream_Decryptor_Triple;
      Read  : out Stream_Element_Offset)
   is
      First : constant Stream_Element_Offset := Self.Buf_Used + 1;
      Last  : constant Stream_Element_Offset := Self.Buf'Length;
      Got   : Stream_Element_Offset := First - 1;
   begin
      if First > Last then
         Read := 0;
         return;
      end if;
      Self.Source.all.Read
        (Self.Buf (First .. Last), Got);
      if Got < First then
         Self.At_EOF := True;
         Read        := 0;
      else
         Read          := Got - First + 1;
         Self.Buf_Used := Got;
      end if;
   end Pull_Source;

   function Make_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Source : not null access Root_Stream_Type'Class)
      return Stream_Decryptor_Triple is
   begin
      return D : Stream_Decryptor_Triple do
         D.Noise_H     := Itb.Seed.Raw_Handle (Noise);
         D.Data1_H     := Itb.Seed.Raw_Handle (Data1);
         D.Data2_H     := Itb.Seed.Raw_Handle (Data2);
         D.Data3_H     := Itb.Seed.Raw_Handle (Data3);
         D.Start1_H    := Itb.Seed.Raw_Handle (Start1);
         D.Start2_H    := Itb.Seed.Raw_Handle (Start2);
         D.Start3_H    := Itb.Seed.Raw_Handle (Start3);
         D.Source      := Source;
         D.Buf         := Allocate (Default_CT_Buffer);
         D.Buf_Used    := 0;
         D.Plain       := null;
         D.Plain_Pos   := 0;
         D.Plain_Last  := 0;
         D.Header_Size := Stream_Element_Offset (Itb.Header_Size);
         D.At_EOF      := False;
         D.Closed      := False;
      end return;
   end Make_Triple;

   function Try_Decode_Chunk
     (Self : in out Stream_Decryptor_Triple) return Boolean
   is
      Hdr_Len : constant Stream_Element_Offset := Self.Header_Size;
      Want    : Natural;
   begin
      if Self.Buf_Used < Hdr_Len then
         return False;
      end if;
      Want := Itb.Parse_Chunk_Len (Self.Buf (1 .. Hdr_Len));
      if Stream_Element_Offset (Want) > Self.Buf'Length then
         Grow_Buf (Self, Stream_Element_Offset (Want));
      end if;
      if Self.Buf_Used < Stream_Element_Offset (Want) then
         return False;
      end if;
      declare
         PT : constant Byte_Array :=
           Decrypt_Triple_Inline
             (Self.Noise_H,
              Self.Data1_H, Self.Data2_H, Self.Data3_H,
              Self.Start1_H, Self.Start2_H, Self.Start3_H,
              Self.Buf (1 .. Stream_Element_Offset (Want)));
         Tail : constant Stream_Element_Offset :=
           Self.Buf_Used - Stream_Element_Offset (Want);
      begin
         if Tail > 0 then
            Self.Buf (1 .. Tail) :=
              Self.Buf
                (Stream_Element_Offset (Want) + 1 .. Self.Buf_Used);
         end if;
         Self.Buf_Used := Tail;
         if Self.Plain /= null then
            Free_Buffer (Self.Plain);
         end if;
         if PT'Length > 0 then
            Self.Plain := new Byte_Array'(PT);
         else
            Self.Plain := new Byte_Array (1 .. 0);
         end if;
         Self.Plain_Pos  := 1;
         Self.Plain_Last := Self.Plain'Last;
         return True;
      end;
   end Try_Decode_Chunk;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Triple;
      Buffer : out Byte_Array;
      Last   : out Stream_Element_Offset)
   is
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      Last := Buffer'First - 1;
      if Self.Closed then
         Itb.Errors.Raise_For (Itb.Status.Easy_Closed);
      end if;
      while Cursor <= Buffer'Last loop
         if Self.Plain /= null
           and then Self.Plain_Pos <= Self.Plain_Last
         then
            declare
               Avail : constant Stream_Element_Offset :=
                 Self.Plain_Last - Self.Plain_Pos + 1;
               Room  : constant Stream_Element_Offset :=
                 Buffer'Last - Cursor + 1;
               Take  : constant Stream_Element_Offset :=
                 Stream_Element_Offset'Min (Avail, Room);
            begin
               Buffer (Cursor .. Cursor + Take - 1) :=
                 Self.Plain
                   (Self.Plain_Pos .. Self.Plain_Pos + Take - 1);
               Cursor          := Cursor + Take;
               Self.Plain_Pos  := Self.Plain_Pos + Take;
               Last            := Cursor - 1;
            end;
         else
            if not Try_Decode_Chunk (Self) then
               if Self.At_EOF then
                  return;
               end if;
               declare
                  Got : Stream_Element_Offset;
               begin
                  if Self.Buf_Used = Self.Buf'Length then
                     Grow_Buf (Self, Self.Buf'Length * 2);
                  end if;
                  Pull_Source (Self, Got);
                  if Got = 0 and then Self.At_EOF then
                     return;
                  end if;
               end;
            end if;
         end if;
      end loop;
   end Read_Plaintext;

   procedure Finish (Self : in out Stream_Decryptor_Triple) is
   begin
      if Self.Closed then
         return;
      end if;
      if Self.Buf_Used > 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      Self.Closed := True;
   end Finish;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Triple) is
   begin
      Self.Closed := True;
      if Self.Buf /= null then
         Free_Buffer (Self.Buf);
      end if;
      if Self.Plain /= null then
         Free_Buffer (Self.Plain);
      end if;
   end Finalize;

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers.
   ---------------------------------------------------------------------

   procedure Encrypt_Stream
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor :=
        Make (Noise, Data, Start, Sink, Chunk_Size);
      --  Buffer lives on the heap so 16 MB defaults don't blow the
      --  task stack. Released deterministically at scope exit.
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream;

   procedure Decrypt_Stream
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor := Make (Noise, Data, Start, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream;

   procedure Encrypt_Stream_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Source     : not null access Root_Stream_Type'Class;
      Sink       : not null access Root_Stream_Type'Class;
      Chunk_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
      Enc : Stream_Encryptor_Triple :=
        Make_Triple (Noise, Data1, Data2, Data3,
                     Start1, Start2, Start3, Sink, Chunk_Size);
      Buf : Byte_Buffer_Access := Allocate (Chunk_Size);
      Got : Stream_Element_Offset;
   begin
      loop
         Got := Buf'First - 1;
         Source.all.Read (Buf.all, Got);
         exit when Got < Buf'First;
         Write_Plaintext (Enc, Buf (Buf'First .. Got));
      end loop;
      Finish (Enc);
      Free_Buffer (Buf);
   exception
      when others =>
         if Buf /= null then
            Free_Buffer (Buf);
         end if;
         raise;
   end Encrypt_Stream_Triple;

   procedure Decrypt_Stream_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Source    : not null access Root_Stream_Type'Class;
      Sink      : not null access Root_Stream_Type'Class;
      Read_Size : Stream_Element_Offset := Default_Chunk_Size)
   is
   begin
      if Read_Size <= 0 then
         Itb.Errors.Raise_For (Itb.Status.Bad_Input);
      end if;
      declare
         Dec : Stream_Decryptor_Triple :=
           Make_Triple (Noise, Data1, Data2, Data3,
                        Start1, Start2, Start3, Source);
         Buf : Byte_Buffer_Access := Allocate (Read_Size);
         Got : Stream_Element_Offset;
      begin
         loop
            Read_Plaintext (Dec, Buf.all, Got);
            exit when Got < Buf'First;
            Write_All (Sink, Buf (Buf'First .. Got));
         end loop;
         Finish (Dec);
         Free_Buffer (Buf);
      exception
         when others =>
            if Buf /= null then
               Free_Buffer (Buf);
            end if;
            raise;
      end;
   end Decrypt_Stream_Triple;

end Itb.Streams;
