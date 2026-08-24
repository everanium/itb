--  bench_message — Encrypt_Message throughput vs plaintext size
--  (Single Message profile) at 1 MiB / 16 MiB / 64 MiB.

with Ada.Streams;

with Common;
with Itb;
with Itb.Pipeline;
with Itb.Runtime;

procedure Bench_Message is

   Sizes : constant array (1 .. 3) of Positive :=
     [1 * 2 ** 20, 16 * 2 ** 20, 64 * 2 ** 20];

   Pipe : Itb.Pipeline.Pipeline;

begin
   --  Bench-scale allocation churn leaks Go scratch heap unboundedly
   --  without a soft memory cap + aggressive GC.
   Itb.Runtime.Set_Memory_Limit (536_870_912);  --  512 MiB soft cap
   Itb.Runtime.Set_GC_Percent (20);

   Pipe.Init
     (Common.Profile_Name ("singlemsg-triple-nomac-v1"),
      Common.Build_Opts);
   Common.Bench_Header;

   for Size of Sizes loop
      declare
         Plain : Itb.Byte_Array_Access :=
           new Itb.Byte_Array
             (1 .. Ada.Streams.Stream_Element_Offset (Size));

         procedure Run is
            --  Build-in-place into a heap object — a stack-declared
            --  result would overflow the primary stack at 64 MiB.
            Wire : Itb.Byte_Array_Access :=
              new Itb.Byte_Array'(Pipe.Encrypt_Message (Plain.all));
         begin
            Itb.Free (Wire);
         end Run;
      begin
         Common.Fill_Random (Plain.all);
         Common.Bench_Case ("message", Size, Run'Access);
         Itb.Free (Plain);
      end;
   end loop;
end Bench_Message;
