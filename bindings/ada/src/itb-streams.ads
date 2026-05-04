--  Itb.Streams — file-like streaming wrappers over the one-shot
--  Itb.Cipher Encrypt / Decrypt entry points.
--
--  ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
--  container size limit). Streaming larger payloads slices the input
--  into chunks at the binding layer, encrypts each chunk through the
--  Itb.Cipher path, and concatenates the results. The reverse
--  operation walks a concatenated chunk stream by reading the chunk
--  header, calling Itb.Parse_Chunk_Len to learn the chunk's body
--  length, reading that many bytes, and decrypting the single chunk.
--
--  Ada idiom note. The wrappers do NOT derive from
--  Ada.Streams.Root_Stream_Type — that would overload the standard
--  Stream_IO Read / Write semantics ambiguously with the ITB
--  encrypt / decrypt pipeline. Instead they accept a caller-owned
--  Ada.Streams.Root_Stream_Type'Class access (the underlying writable
--  / readable byte sink / source) at construction and expose explicit
--  Write_Plaintext / Read_Plaintext primitives that flow plaintext
--  through the (encrypt → underlying stream) or (underlying stream →
--  decrypt) pipeline.
--
--  Both struct-based wrappers (Stream_Encryptor / Stream_Decryptor and
--  their Triple counterparts) and free-subprogram convenience drivers
--  (Encrypt_Stream / Decrypt_Stream / Triple variants) are provided.
--  Memory peak is bounded by Chunk_Size (default 16 MB) regardless of
--  the total payload length.
--
--  The Triple Ouroboros (7-seed) variants share the same I/O contract
--  and only differ in the seed list passed to the constructor.
--
--  Warning. Do not call Itb.Set_Nonce_Bits between writes on the same
--  stream. Each chunk is encrypted under the active nonce-size at the
--  moment it is flushed; switching nonce-bits mid-stream produces a
--  chunk header layout the paired decryptor (which snapshots
--  Itb.Header_Size at construction) cannot parse.
--
--  Seed lifetime contract. Every Seed passed to Make / Make_Triple
--  (and to the convenience drivers Encrypt_Stream / Decrypt_Stream /
--  the Triple variants) MUST remain in scope, un-finalized, for the
--  whole lifetime of the resulting stream wrapper. The wrappers
--  cache the raw libitb handles internally; finalising the originating
--  Seed before the stream finishes its work would free the handle
--  while the stream is still using it (a stochastic use-after-free).
--  Rust enforces the parallel constraint via &'a Seed lifetime
--  borrows; Ada relies on caller discipline. The same caller-owns
--  rule already applies to Itb.Seed.Attach_Lock_Seed for the
--  dedicated lockSeed channel.

private with Ada.Finalization;
private with Itb.Sys;

with Ada.Streams;
with Itb.Seed;

package Itb.Streams is
   pragma Preelaborate;

   --  Default chunk size — matches itb.DefaultChunkSize on the Go side
   --  (16 MB), the size at which ITB's barrier-encoded container layout
   --  stays well within the per-chunk pixel cap.
   Default_Chunk_Size : constant Ada.Streams.Stream_Element_Offset :=
     Ada.Streams.Stream_Element_Offset (16 * 1024 * 1024);

   ---------------------------------------------------------------------
   --  Single Ouroboros — chunked writer.
   ---------------------------------------------------------------------

   --  Buffers plaintext until at least Chunk_Size bytes are available,
   --  then encrypts and emits one chunk to the underlying Sink. The
   --  trailing partial buffer is flushed as a final chunk on Finish
   --  (so the on-the-wire chunk count is ceil(total / Chunk_Size)).
   type Stream_Encryptor is tagged limited private;

   --  Constructs a fresh stream encryptor wrapping the given Sink.
   --  Chunk_Size must be positive; the default matches the Go-side
   --  itb.DefaultChunkSize.
   function Make
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size) return Stream_Encryptor;

   --  Appends Data to the internal buffer, encrypting and emitting
   --  every full Chunk_Size-sized slice that becomes available.
   procedure Write_Plaintext
     (Self : in out Stream_Encryptor;
      Data : Byte_Array);

   --  Encrypts and emits any remaining buffered bytes as the final
   --  chunk. Idempotent — a second call is a no-op.
   procedure Finish (Self : in out Stream_Encryptor);

   ---------------------------------------------------------------------
   --  Single Ouroboros — chunked reader.
   ---------------------------------------------------------------------

   --  Pulls ciphertext bytes from the underlying Source on demand, one
   --  full chunk at a time, decrypts it, and refills the caller's
   --  Buffer with the recovered plaintext. Returns Buffer'First - 1 in
   --  Last on EOF.
   type Stream_Decryptor is tagged limited private;

   --  Constructs a fresh stream decryptor wrapping the given Source.
   --  The chunk-header size is snapshotted at construction so the
   --  decryptor uses the same header layout the matching encryptor
   --  saw — changing Itb.Set_Nonce_Bits mid-stream would break decoding
   --  anyway.
   function Make
     (Noise  : Itb.Seed.Seed;
      Data   : Itb.Seed.Seed;
      Start  : Itb.Seed.Seed;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor;

   --  Reads enough ciphertext from Source to decrypt at least one
   --  chunk, then copies recovered plaintext into Buffer. Last is set
   --  to the index of the last byte filled (Buffer'First - 1 if EOF
   --  was reached before any plaintext could be produced). Returns
   --  fewer than Buffer'Length bytes when a chunk boundary or EOF is
   --  hit; callers that need exactly Buffer'Length bytes loop until
   --  Last < Buffer'Last or EOF.
   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   --  Finalises the decryptor. Raises Itb_Error / Bad_Input when
   --  leftover bytes do not form a complete chunk — streaming ITB
   --  ciphertext cannot have a half-chunk tail.
   procedure Finish (Self : in out Stream_Decryptor);

   ---------------------------------------------------------------------
   --  Triple Ouroboros — chunked writer.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) counterpart of Stream_Encryptor.
   type Stream_Encryptor_Triple is tagged limited private;

   function Make_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size)
      return Stream_Encryptor_Triple;

   procedure Write_Plaintext
     (Self : in out Stream_Encryptor_Triple;
      Data : Byte_Array);

   procedure Finish (Self : in out Stream_Encryptor_Triple);

   ---------------------------------------------------------------------
   --  Triple Ouroboros — chunked reader.
   ---------------------------------------------------------------------

   --  Triple-Ouroboros (7-seed) counterpart of Stream_Decryptor.
   type Stream_Decryptor_Triple is tagged limited private;

   function Make_Triple
     (Noise  : Itb.Seed.Seed;
      Data1  : Itb.Seed.Seed;
      Data2  : Itb.Seed.Seed;
      Data3  : Itb.Seed.Seed;
      Start1 : Itb.Seed.Seed;
      Start2 : Itb.Seed.Seed;
      Start3 : Itb.Seed.Seed;
      Source : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Decryptor_Triple;

   procedure Read_Plaintext
     (Self   : in out Stream_Decryptor_Triple;
      Buffer : out Byte_Array;
      Last   : out Ada.Streams.Stream_Element_Offset);

   procedure Finish (Self : in out Stream_Decryptor_Triple);

   ---------------------------------------------------------------------
   --  Free-subprogram convenience drivers — read entire Source until
   --  EOF, encrypt / decrypt in chunks, and write to Sink.
   ---------------------------------------------------------------------

   procedure Encrypt_Stream
     (Noise      : Itb.Seed.Seed;
      Data       : Itb.Seed.Seed;
      Start      : Itb.Seed.Seed;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream
     (Noise     : Itb.Seed.Seed;
      Data      : Itb.Seed.Seed;
      Start     : Itb.Seed.Seed;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

   procedure Encrypt_Stream_Triple
     (Noise      : Itb.Seed.Seed;
      Data1      : Itb.Seed.Seed;
      Data2      : Itb.Seed.Seed;
      Data3      : Itb.Seed.Seed;
      Start1     : Itb.Seed.Seed;
      Start2     : Itb.Seed.Seed;
      Start3     : Itb.Seed.Seed;
      Source     : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink       : not null access Ada.Streams.Root_Stream_Type'Class;
      Chunk_Size : Ada.Streams.Stream_Element_Offset :=
                     Default_Chunk_Size);

   procedure Decrypt_Stream_Triple
     (Noise     : Itb.Seed.Seed;
      Data1     : Itb.Seed.Seed;
      Data2     : Itb.Seed.Seed;
      Data3     : Itb.Seed.Seed;
      Start1    : Itb.Seed.Seed;
      Start2    : Itb.Seed.Seed;
      Start3    : Itb.Seed.Seed;
      Source    : not null access Ada.Streams.Root_Stream_Type'Class;
      Sink      : not null access Ada.Streams.Root_Stream_Type'Class;
      Read_Size : Ada.Streams.Stream_Element_Offset :=
                    Default_Chunk_Size);

private

   --  Indefinite holder for the per-instance chunk / buffer queue.
   --  Pre-sized to Chunk_Size on construction; trimmed in place as
   --  chunks drain. Stored as Byte_Array on the heap because the
   --  buffer length grows / shrinks at runtime independently of the
   --  controlled type's discriminant constraints.
   type Byte_Buffer_Access is access Byte_Array;

   --  Common Single-Ouroboros encryptor state.
   type Stream_Encryptor is new Ada.Finalization.Limited_Controlled with
      record
         Noise_H    : Itb.Sys.Handle := 0;
         Data_H     : Itb.Sys.Handle := 0;
         Start_H    : Itb.Sys.Handle := 0;
         Sink       : access Ada.Streams.Root_Stream_Type'Class := null;
         Chunk_Size : Ada.Streams.Stream_Element_Offset := 0;
         Buf        : Byte_Buffer_Access := null;
         Buf_Used   : Ada.Streams.Stream_Element_Offset := 0;
         Closed     : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor);

   type Stream_Decryptor is new Ada.Finalization.Limited_Controlled with
      record
         Noise_H     : Itb.Sys.Handle := 0;
         Data_H      : Itb.Sys.Handle := 0;
         Start_H     : Itb.Sys.Handle := 0;
         Source      : access Ada.Streams.Root_Stream_Type'Class := null;
         Buf         : Byte_Buffer_Access := null;
         Buf_Used    : Ada.Streams.Stream_Element_Offset := 0;
         Plain       : Byte_Buffer_Access := null;
         Plain_Pos   : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last  : Ada.Streams.Stream_Element_Offset := 0;
         Header_Size : Ada.Streams.Stream_Element_Offset := 0;
         At_EOF      : Boolean := False;
         Closed      : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor);

   type Stream_Encryptor_Triple is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H    : Itb.Sys.Handle := 0;
         Data1_H    : Itb.Sys.Handle := 0;
         Data2_H    : Itb.Sys.Handle := 0;
         Data3_H    : Itb.Sys.Handle := 0;
         Start1_H   : Itb.Sys.Handle := 0;
         Start2_H   : Itb.Sys.Handle := 0;
         Start3_H   : Itb.Sys.Handle := 0;
         Sink       : access Ada.Streams.Root_Stream_Type'Class := null;
         Chunk_Size : Ada.Streams.Stream_Element_Offset := 0;
         Buf        : Byte_Buffer_Access := null;
         Buf_Used   : Ada.Streams.Stream_Element_Offset := 0;
         Closed     : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Encryptor_Triple);

   type Stream_Decryptor_Triple is new
     Ada.Finalization.Limited_Controlled with
      record
         Noise_H     : Itb.Sys.Handle := 0;
         Data1_H     : Itb.Sys.Handle := 0;
         Data2_H     : Itb.Sys.Handle := 0;
         Data3_H     : Itb.Sys.Handle := 0;
         Start1_H    : Itb.Sys.Handle := 0;
         Start2_H    : Itb.Sys.Handle := 0;
         Start3_H    : Itb.Sys.Handle := 0;
         Source      : access Ada.Streams.Root_Stream_Type'Class := null;
         Buf         : Byte_Buffer_Access := null;
         Buf_Used    : Ada.Streams.Stream_Element_Offset := 0;
         Plain       : Byte_Buffer_Access := null;
         Plain_Pos   : Ada.Streams.Stream_Element_Offset := 0;
         Plain_Last  : Ada.Streams.Stream_Element_Offset := 0;
         Header_Size : Ada.Streams.Stream_Element_Offset := 0;
         At_EOF      : Boolean := False;
         Closed      : Boolean := False;
      end record;

   overriding procedure Finalize (Self : in out Stream_Decryptor_Triple);

end Itb.Streams;
