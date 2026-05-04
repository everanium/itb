--  Itb.Encryptor — Easy Mode wrapper over the libitb C ABI.
--
--  Mirrors bindings/rust/src/encryptor.rs. One Make / Mixed_Single /
--  Mixed_Triple call replaces the lower-level seven-line setup
--  ceremony (hash factory, three or seven seeds, MAC closure,
--  container-config wiring) and yields an Encryptor value that owns
--  its own per-instance configuration. Two encryptors with different
--  settings can be used in parallel without cross-contamination of
--  the process-wide ITB configuration.
--
--  Quick start (Single Ouroboros + HMAC-BLAKE3):
--
--     declare
--        Enc : Itb.Encryptor.Encryptor :=
--          Itb.Encryptor.Make (Primitive => "blake3", Key_Bits => 1024);
--        CT  : constant Byte_Array := Enc.Encrypt_Auth (Plaintext);
--        PT  : constant Byte_Array := Enc.Decrypt_Auth (CT);
--     begin
--        ...
--     end;  --  Enc finalised here, key material wiped on the Go side.
--
--  Lifecycle is RAII: Encryptor inherits from
--  Ada.Finalization.Limited_Controlled, so leaving the value's scope
--  releases the underlying libitb handle deterministically. Close is
--  the explicit zeroing path that wipes PRF / MAC / seed material on
--  the Go side and the per-instance output cache on the Ada side.
--
--  Output-buffer cache. The cipher methods reuse a per-encryptor
--  Byte_Array buffer to skip the size-probe round-trip every cipher
--  call would otherwise pay; the buffer grows on demand from a 1.25x
--  upper bound (the empirical ITB ciphertext-expansion factor measured
--  at <= 1.155 across every primitive / mode / nonce / payload-size
--  combination) and survives between calls. Each cipher call returns
--  a fresh Byte_Array copy of the current result, so the cache is
--  never exposed to the caller; the cached bytes (the most recent
--  ciphertext or plaintext) are wiped on grow, on Close, and on
--  Finalize. Callers handling sensitive plaintext under a heap-scan
--  threat model should call Close immediately after the last decrypt
--  rather than relying on Finalize at scope exit.
--
--  Easy Mode auto-couple. Calling Set_Lock_Seed (1) /
--  Set_Bit_Soup (1) / Set_Lock_Soup (1) auto-engages Bit Soup +
--  Lock Soup on the on-direction. Documented "thinks-for-the-dumb-
--  user" behaviour matching every other binding.
--
--  Default MAC override. When Mac_Name = "" is passed to Make /
--  Mixed_Single / Mixed_Triple, the binding substitutes
--  "hmac-blake3" before forwarding to libitb. HMAC-BLAKE3 measures
--  the lightest authenticated-mode overhead in the bench surface;
--  routing the default through it gives the constructor-without-
--  arguments path the lowest cost.

private with Ada.Finalization;

with Ada.Strings.Unbounded;

with Itb.Sys;

package Itb.Encryptor is
   pragma Preelaborate;

   --  Mode parameter contract: 1 (Single Ouroboros, default) or
   --  3 (Triple Ouroboros). Other values surface as Constraint_Error
   --  from the static predicate before any FFI call is made.
   subtype Mode_Type is Integer range 1 .. 3
     with Static_Predicate => Mode_Type in 1 | 3;

   --  Easy Mode encryptor handle. Limited type — passed by reference,
   --  never copied; release deterministic at scope exit.
   type Encryptor is tagged limited private;

   --  Peeked metadata record returned by Peek_Config. Mirrors the
   --  four-tuple Rust returns: primitive name, ITB key width in bits,
   --  Ouroboros mode (1 / 3), and the canonical MAC name.
   type Peeked_Config is record
      Primitive : Ada.Strings.Unbounded.Unbounded_String;
      Key_Bits  : Integer := 0;
      Mode      : Integer := 0;
      MAC_Name  : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   ---------------------------------------------------------------------
   --  Constructors
   ---------------------------------------------------------------------

   --  Single-primitive constructor. Primitive is a canonical hash name
   --  from Itb.List_Hashes ("areion256", "areion512", "siphash24",
   --  "aescmac", "blake2b256", "blake2b512", "blake2s", "blake3",
   --  "chacha20"). Key_Bits is the ITB key width in bits (512, 1024,
   --  2048; multiple of the primitive's native digest width).
   --
   --  Mac_Name is a canonical MAC name from Itb.List_MACs ("kmac256",
   --  "hmac-sha256", "hmac-blake3"). The empty string "" is the
   --  default and triggers the binding-side override to "hmac-blake3"
   --  before forwarding to libitb.
   --
   --  Mode is 1 (Single Ouroboros, 3 seeds — noise / data / start) or
   --  3 (Triple Ouroboros, 7 seeds — noise + 3 pairs of data / start).
   --  Other values are rejected by the Mode_Type static predicate
   --  with Constraint_Error before any FFI call.
   function Make
     (Primitive : String;
      Key_Bits  : Integer;
      Mac_Name  : String    := "";
      Mode      : Mode_Type := 1) return Encryptor;

   --  Single-Ouroboros mixed-primitive constructor. Allocates one seed
   --  slot per (N, D, S) primitive name. Prim_L is the optional
   --  dedicated lockSeed primitive — pass "" for "no lockSeed" and a
   --  non-empty primitive name to allocate a 4th seed slot under that
   --  primitive (auto-couples Bit Soup + Lock Soup on the on-direction).
   --
   --  All four primitive names must resolve to the same native hash
   --  width; mixed widths surface as Itb_Error / Seed_Width_Mix.
   --
   --  Mac_Name follows the same default-override rule as Make.
   function Mixed_Single
     (Prim_N   : String;
      Prim_D   : String;
      Prim_S   : String;
      Prim_L   : String;
      Key_Bits : Integer;
      Mac_Name : String := "") return Encryptor;

   --  Triple-Ouroboros counterpart of Mixed_Single. Accepts seven
   --  per-slot primitive names (noise + 3 data + 3 start) plus the
   --  optional Prim_L lockSeed primitive. See Mixed_Single for the
   --  construction contract.
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
      Mac_Name : String := "") return Encryptor;

   ---------------------------------------------------------------------
   --  Cipher entry points
   ---------------------------------------------------------------------

   --  Encrypts Plaintext using the encryptor's configured primitive,
   --  key_bits, mode, and per-instance Config snapshot. Plain mode —
   --  does not attach a MAC tag; for authenticated encryption use
   --  Encrypt_Auth.
   function Encrypt
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array;

   --  Decrypts Ciphertext produced by Encrypt under the same encryptor.
   function Decrypt
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array;

   --  Encrypts Plaintext and attaches a MAC tag using the encryptor's
   --  bound MAC closure.
   function Encrypt_Auth
     (Self      : in out Encryptor;
      Plaintext : Byte_Array) return Byte_Array;

   --  Verifies and decrypts Ciphertext produced by Encrypt_Auth.
   --  Surfaces Itb_Error / MAC_Failure on tampered ciphertext or
   --  wrong MAC key.
   function Decrypt_Auth
     (Self       : in out Encryptor;
      Ciphertext : Byte_Array) return Byte_Array;

   ---------------------------------------------------------------------
   --  Per-instance configuration setters
   ---------------------------------------------------------------------

   --  Override the nonce size for this encryptor's subsequent
   --  encrypt / decrypt calls. Valid values: 128, 256, 512. Mutates
   --  only this encryptor's Config copy; process-wide
   --  Itb.Set_Nonce_Bits is unaffected.
   procedure Set_Nonce_Bits (Self : Encryptor; N : Integer);

   --  Override the CSPRNG barrier-fill margin for this encryptor.
   --  Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
   --  not need the same value as sender.
   procedure Set_Barrier_Fill (Self : Encryptor; N : Integer);

   --  0 = byte-level split (default); non-zero = bit-level Bit Soup
   --  split.
   procedure Set_Bit_Soup (Self : Encryptor; Mode : Integer);

   --  0 = off (default); non-zero = on. Auto-couples Bit_Soup = 1 on
   --  this encryptor.
   procedure Set_Lock_Soup (Self : Encryptor; Mode : Integer);

   --  0 = off; 1 = on (allocates a dedicated lockSeed and routes the
   --  bit-permutation overlay through it; auto-couples Lock_Soup = 1
   --  + Bit_Soup = 1 on this encryptor). Calling after the first
   --  encrypt surfaces Itb_Error / Easy_LockSeed_After_Encrypt.
   procedure Set_Lock_Seed (Self : Encryptor; Mode : Integer);

   --  Per-instance streaming chunk-size override (0 = auto-detect via
   --  itb.ChunkSize on the Go side).
   procedure Set_Chunk_Size (Self : Encryptor; N : Integer);

   ---------------------------------------------------------------------
   --  Read-only accessors
   ---------------------------------------------------------------------

   --  Returns the canonical primitive name bound at construction.
   function Primitive (Self : Encryptor) return String;

   --  Per-slot primitive accessor. Slot ordering is canonical —
   --  0 = noiseSeed, then dataSeed{,1..3}, then startSeed{,1..3},
   --  with the optional dedicated lockSeed at the trailing slot. For
   --  single-primitive encryptors every slot returns the same
   --  Primitive value; for encryptors built via Mixed_Single /
   --  Mixed_Triple each slot returns its independently-chosen
   --  primitive name.
   function Primitive_At (Self : Encryptor; Slot : Integer) return String;

   --  Returns the ITB key width in bits.
   function Key_Bits (Self : Encryptor) return Integer;

   --  Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros).
   function Mode (Self : Encryptor) return Integer;

   --  Returns the canonical MAC name bound at construction.
   function MAC_Name (Self : Encryptor) return String;

   --  Number of seed slots: 3 (Single without LockSeed),
   --  4 (Single with LockSeed), 7 (Triple without LockSeed),
   --  8 (Triple with LockSeed).
   function Seed_Count (Self : Encryptor) return Integer;

   --  True when the encryptor's primitive uses fixed PRF keys per
   --  seed slot (every shipped primitive except siphash24).
   function Has_PRF_Keys (Self : Encryptor) return Boolean;

   --  True when the encryptor was constructed via Mixed_Single /
   --  Mixed_Triple (per-slot primitive selection); False for
   --  single-primitive encryptors built via Make.
   function Is_Mixed (Self : Encryptor) return Boolean;

   --  Nonce size in bits configured for this encryptor — either the
   --  value from the most recent Set_Nonce_Bits call, or the
   --  process-wide Itb.Get_Nonce_Bits reading at construction time
   --  when no per-instance override has been issued.
   function Nonce_Bits (Self : Encryptor) return Integer;

   --  Per-instance ciphertext-chunk header size in bytes
   --  (nonce + 2-byte width + 2-byte height). Tracks this
   --  encryptor's own Nonce_Bits, NOT the process-wide
   --  Itb.Header_Size — important when Set_Nonce_Bits has overridden
   --  the default.
   function Header_Size (Self : Encryptor) return Integer;

   ---------------------------------------------------------------------
   --  Component / key extractors (defensive copies)
   ---------------------------------------------------------------------

   --  Returns the uint64 components of one seed slot. Slot index
   --  follows the canonical ordering: Single = [noise, data, start];
   --  Triple = [noise, data1, data2, data3, start1, start2, start3];
   --  the dedicated lockSeed slot, when present, is appended at the
   --  trailing index (3 for Single, 7 for Triple). Consult
   --  Seed_Count to determine the valid slot range.
   function Get_Seed_Components
     (Self : Encryptor;
      Slot : Integer) return Component_Array;

   --  Returns the fixed PRF key bytes for one seed slot. Surfaces
   --  Itb_Error / Bad_Input when the primitive has no fixed PRF keys
   --  (siphash24 — caller should consult Has_PRF_Keys first) or when
   --  Slot is out of range.
   function Get_PRF_Key
     (Self : Encryptor;
      Slot : Integer) return Byte_Array;

   --  Returns the encryptor's bound MAC fixed key. Save these bytes
   --  alongside the seed material for cross-process restore via
   --  Export_State / Import_State.
   function Get_MAC_Key (Self : Encryptor) return Byte_Array;

   ---------------------------------------------------------------------
   --  Streaming helpers
   ---------------------------------------------------------------------

   --  Per-instance counterpart of Itb.Parse_Chunk_Len. Inspects the
   --  fixed-size [nonce(N) || width(2) || height(2)] header of a
   --  ciphertext chunk produced by this encryptor and returns the
   --  total chunk length on the wire. Buffer must contain at least
   --  Header_Size bytes; only the header is consulted, the body
   --  bytes need not be present.
   function Parse_Chunk_Len
     (Self   : Encryptor;
      Header : Byte_Array) return Natural;

   ---------------------------------------------------------------------
   --  Lifecycle
   ---------------------------------------------------------------------

   --  Zeroes the encryptor's PRF keys, MAC key, seed components, and
   --  the per-instance output cache, and marks the encryptor as
   --  closed. Idempotent — multiple Close calls return without
   --  raising.
   procedure Close (Self : in out Encryptor);

   ---------------------------------------------------------------------
   --  State persistence
   ---------------------------------------------------------------------

   --  Serialises the encryptor's full state (PRF keys, seed
   --  components, MAC key, dedicated lockSeed material when active)
   --  as a JSON blob. Per-instance configuration knobs (Nonce_Bits,
   --  Barrier_Fill, Bit_Soup, Lock_Soup, Chunk_Size) are NOT carried
   --  in the v1 blob — both sides communicate them via deployment
   --  config. LockSeed is carried because activating it changes the
   --  structural seed count.
   function Export_State (Self : Encryptor) return Byte_Array;

   --  Replaces the encryptor's PRF keys, seed components, MAC key,
   --  and (optionally) dedicated lockSeed material with the values
   --  carried in a JSON blob produced by a prior Export_State call.
   --  On any failure the encryptor's pre-import state is unchanged
   --  (the underlying Go-side Encryptor.Import is transactional).
   --  Mismatch on primitive / key_bits / mode / mac surfaces as
   --  Itb_Easy_Mismatch_Error with the offending field name reachable
   --  via Itb.Errors.Field.
   procedure Import_State (Self : in out Encryptor; Blob : Byte_Array);

   --  Parses a state blob's metadata (primitive, key_bits, mode, mac)
   --  without performing full validation, allowing a caller to inspect
   --  a saved blob before constructing a matching encryptor.
   --
   --  Asymmetry vs Import_State: the peek path conflates "version too
   --  new" with "malformed" and surfaces both as
   --  Itb_Blob_Malformed_Error / Easy_Malformed; only Import_State
   --  differentiates the two via the dedicated Easy_Version_Too_New
   --  status.
   function Peek_Config (Blob : Byte_Array) return Peeked_Config;

private

   type Byte_Array_Access is access Byte_Array;

   type Encryptor is new Ada.Finalization.Limited_Controlled with record
      Handle : Itb.Sys.Handle    := 0;
      Cache  : Byte_Array_Access := null;
   end record;

   overriding procedure Finalize (Self : in out Encryptor);

end Itb.Encryptor;
