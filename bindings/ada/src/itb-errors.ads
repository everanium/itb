--  Itb.Errors — exception types raised by every Itb.* safe wrapper on
--  a non-OK libitb status, plus the Raise_For helper that maps a
--  numeric status code to the right exception with the right
--  structured payload attached.
--
--  Cross-binding parity: this 5-exception layout mirrors the
--  Python / C# / Node.js typed-exception hierarchy
--    base                   ← Itb_Error
--    EasyMismatch (.field)  ← Itb_Easy_Mismatch_Error
--    BlobModeMismatch       ← Itb_Blob_Mode_Mismatch_Error
--    BlobMalformed          ← Itb_Blob_Malformed_Error
--    BlobVersionTooNew      ← Itb_Blob_Version_Too_New_Error
--  Rust uses an enum-variant ITBError instead of subclassing; the Ada
--  multi-exception form is closer to the Python idiom but preserves
--  the Rust "match by code" capability through the Status_Code
--  accessor below.
--
--  Structured payload format. The Exception_Message attached to every
--  raise carries three pipe-separated fields, e.g.
--      "12||malformed easy-mode state blob"
--      "17|primitive|expected blake3, got chacha20"
--      "0||generic libitb error"
--  decoded by the Status_Code, Field, and Message accessor functions
--  in this package.

with Ada.Exceptions;

package Itb.Errors is
   pragma Preelaborate;
   pragma SPARK_Mode (Off);

   --  Base exception raised by every Itb.* subprogram on a non-OK
   --  status that does not have a more specific typed exception below.
   Itb_Error                      : exception;

   --  Easy Mode encryptor: persisted-config field disagrees with the
   --  receiving encryptor (peek / import / chunk-len boundary). The
   --  mismatched field name is attached via the structured payload
   --  and accessible through Field.
   Itb_Easy_Mismatch_Error        : exception;

   --  Native Blob: persisted mode (Single / Triple) or width does not
   --  match the receiving Blob.
   Itb_Blob_Mode_Mismatch_Error   : exception;

   --  Native Blob: payload fails internal sanity checks (magic / CRC
   --  / structural).
   Itb_Blob_Malformed_Error       : exception;

   --  Native Blob: persisted format version is newer than this build
   --  of libitb knows how to parse.
   Itb_Blob_Version_Too_New_Error : exception;

   --  Accessors over the structured Exception_Message format. Return
   --  zero / empty when the payload is malformed (e.g. an Itb_Error
   --  re-raised with a non-canonical message).

   function Status_Code
     (E : Ada.Exceptions.Exception_Occurrence) return Natural;

   function Field
     (E : Ada.Exceptions.Exception_Occurrence) return String;

   function Message
     (E : Ada.Exceptions.Exception_Occurrence) return String;

   --  Internal helper used by every safe wrapper: takes the libitb
   --  status code, looks up the corresponding diagnostic message via
   --  ITB_LastError and (for Easy_Mismatch) ITB_Easy_LastMismatchField,
   --  picks the right typed exception, and raises with the structured
   --  payload assembled. Never returns when Status /= 0; raises
   --  Program_Error when called with Status = 0 (defensive guard).
   procedure Raise_For (Status : Integer)
   with No_Return,
        SPARK_Mode => Off;

end Itb.Errors;
