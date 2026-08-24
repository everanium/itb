--  bench_stream — incremental stream-pump encrypt throughput vs
--  plaintext size (Streaming Non-AEAD profile by default) at
--  1 MiB / 16 MiB / 64 MiB. Each iteration opens a session, feeds
--  the plaintext in 1 MiB slices, drains produced wire into an
--  accumulation buffer, and finishes the session — mirroring the
--  reference pump loops.

with Ada.Streams;

with Common;
with Itb;
with Itb.Pipeline;
with Itb.Runtime;
with Itb.Stream;

procedure Bench_Stream is

   use type Ada.Streams.Stream_Element_Offset;

   subtype Offset is Ada.Streams.Stream_Element_Offset;

   Slice : constant Offset := 2 ** 20;

   Sizes : constant array (1 .. 3) of Positive :=
     [1 * 2 ** 20, 16 * 2 ** 20, 64 * 2 ** 20];

   Pipe : Itb.Pipeline.Pipeline;

begin
   --  Bench-scale allocation churn leaks Go scratch heap unboundedly
   --  without a soft memory cap + aggressive GC.
   Itb.Runtime.Set_Memory_Limit (536_870_912);  --  512 MiB soft cap
   Itb.Runtime.Set_GC_Percent (20);

   Pipe.Init
     (Common.Profile_Name ("streaming-noaead-triple-v1"),
      Common.Build_Opts);
   Common.Bench_Header;

   for Size of Sizes loop
      declare
         N       : constant Offset := Offset (Size);
         Plain   : Itb.Byte_Array_Access := new Itb.Byte_Array (1 .. N);
         Scratch : Itb.Byte_Array_Access :=
           new Itb.Byte_Array (1 .. Slice);

         procedure Run is
            Sess : Itb.Stream.Encrypt_Stream;
            Wire : Itb.Byte_Array_Access :=
              new Itb.Byte_Array (1 .. N + N / 4 + 131_072);
            Wpos : Offset := 0;
            Pos  : Offset := 1;
            Last : Offset;
            Fin  : Boolean;
         begin
            Sess.Begin_Encrypt (Pipe);
            while Pos <= N loop
               declare
                  Hi : constant Offset := Offset'Min (Pos + Slice - 1, N);
               begin
                  Sess.Write (Plain.all (Pos .. Hi));
                  Pos := Hi + 1;
               end;
               loop
                  Sess.Read (Scratch.all, Last, Fin);
                  exit when Last < Scratch.all'First;
                  Wire.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end loop;
            end loop;
            Sess.Finish;
            loop
               Sess.Read (Scratch.all, Last, Fin);
               if Last >= Scratch.all'First then
                  Wire.all (Wpos + 1 .. Wpos + Last) :=
                    Scratch.all (1 .. Last);
                  Wpos := Wpos + Last;
               end if;
               exit when Fin;
            end loop;
            Itb.Free (Wire);
         end Run;
      begin
         Common.Fill_Random (Plain.all);
         Common.Bench_Case ("stream_pump", Size, Run'Access);
         Itb.Free (Plain);
         Itb.Free (Scratch);
      end;
   end loop;
end Bench_Stream;
