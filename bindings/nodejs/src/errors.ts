// Exception hierarchy for libitb FFI failures.
//
// Every fallible libitb call returns a non-zero status code on
// failure; the higher-level wrappers translate the code into one of
// the typed exceptions below via `check(status)` or
// `errorFromStatus(status)`.
//
// The Node.js binding mirrors the Python binding's typed-subclass
// hierarchy for selective `instanceof` matching (`ITBError` base +
// `ITBEasyMismatchError` with `.field` + `ITBBlobModeMismatchError`
// + `ITBBlobMalformedError` + `ITBBlobVersionTooNewError`).
//
// Threading caveat. The textual `.message` is read from a
// process-wide atomic inside libitb that follows the C `errno`
// discipline: the most recent non-OK Status across the whole
// process wins, and a sibling thread that calls into libitb between
// the failing call and the diagnostic read overwrites the message.
// The structural `.code` on the failing call is unaffected — only
// the textual message is racy.

import { ITB_Easy_LastMismatchField, ITB_LastError } from './native.js';
import { readString } from './read-string.js';
import { Status } from './status.js';

export class ITBError extends Error {
  readonly code: number;

  constructor(code: number, message?: string) {
    super(formatMessage(code, message));
    this.code = code;
    this.name = 'ITBError';
    // Restore prototype chain after `super()` (Error's constructor
    // resets the prototype to Error.prototype on some V8 paths).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised by `Encryptor.importState` / `Encryptor.peekConfig` when
 * the supplied state blob disagrees with the live encryptor's
 * configuration on at least one field. `.field` carries the
 * offending JSON field name (e.g. `"primitive"`, `"key_bits"`,
 * `"mode"`, `"mac"`).
 *
 * Field-attribution race. The `.field` value is read from
 * `ITB_Easy_LastMismatchField` at exception construction time — a
 * process-wide atomic that follows the same C `errno` discipline as
 * `ITB_LastError`. Two concurrent failing imports across separate
 * worker threads can cross the field-name strings; callers that
 * need reliable field attribution under concurrent imports must
 * serialise the import calls externally.
 */
export class ITBEasyMismatchError extends ITBError {
  readonly field: string | null;

  constructor(code: number, message: string | undefined, field: string | null) {
    super(code, formatWithField(message, field));
    this.field = field;
    this.name = 'ITBEasyMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when a Single-mode blob is fed into a
 * Triple-mode handle (or vice-versa). */
export class ITBBlobModeMismatchError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobModeMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when the blob's framing / length /
 * magic-byte shape fails validation. */
export class ITBBlobMalformedError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobMalformedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when the blob's version field is newer
 * than the running binding can decode. */
export class ITBBlobVersionTooNewError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobVersionTooNewError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function formatMessage(code: number, message: string | undefined): string {
  if (!message || message.length === 0) {
    return `itb: status=${code}`;
  }
  return `itb: status=${code} (${message})`;
}

function formatWithField(message: string | undefined, field: string | null): string | undefined {
  if (field === null || field.length === 0) {
    return message;
  }
  if (!message || message.length === 0) {
    return `mismatch on field '${field}'`;
  }
  return `${message} (field '${field}')`;
}

export function lastError(): string {
  try {
    const { rc, value } = readString((out, cap, outLen) =>
      ITB_LastError(out, cap, outLen),
    );
    if (rc !== Status.Ok) {
      return '';
    }
    return value;
  } catch {
    return '';
  }
}

function lastMismatchField(): string | null {
  try {
    const { rc, value } = readString((out, cap, outLen) =>
      ITB_Easy_LastMismatchField(out, cap, outLen),
    );
    if (rc !== Status.Ok || value.length === 0) {
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

export function errorFromStatus(code: number): ITBError {
  const msg = lastError();
  switch (code) {
    case Status.EasyMismatch:
      return new ITBEasyMismatchError(code, msg, lastMismatchField());
    case Status.BlobModeMismatch:
      return new ITBBlobModeMismatchError(code, msg);
    case Status.BlobMalformed:
      return new ITBBlobMalformedError(code, msg);
    case Status.BlobVersionTooNew:
      return new ITBBlobVersionTooNewError(code, msg);
    default:
      return new ITBError(code, msg);
  }
}

export function check(status: number): void {
  if (status === Status.Ok) {
    return;
  }
  throw errorFromStatus(status);
}
