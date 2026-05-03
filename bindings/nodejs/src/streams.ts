// File-like streaming wrappers over the one-shot ITB encrypt /
// decrypt API.
//
// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
// container size limit). Streaming larger payloads simply means
// slicing the input into chunks at the binding layer, encrypting
// each chunk through the regular FFI path, and concatenating the
// results. The reverse operation walks a concatenated chunk stream
// by reading the chunk header, calling `parseChunkLen` to learn the
// chunk's body length, reading that many bytes, and decrypting the
// single chunk.
//
// Both class-based wrappers (`StreamEncryptor` / `StreamDecryptor`
// and their Triple-Ouroboros counterparts `StreamEncryptorTriple` /
// `StreamDecryptorTriple`) and the convenience helpers
// (`encryptStream` / `decryptStream` plus the Triple variants) are
// provided. Memory peak per call is bounded by `chunkSize` (default
// 16 MiB — see `DEFAULT_CHUNK_SIZE`), regardless of the total
// payload length.
//
// The Triple-Ouroboros (7-seed) variants share the same I/O
// contract and only differ in the seed list passed to the
// constructor.
//
// Threading caveat. Do not call `setNonceBits` between writes on
// the same stream. The chunks are encrypted under the active
// nonce-size at the moment each chunk is flushed; switching
// nonce-bits mid-stream produces a chunk header layout the paired
// decryptor (which snapshots `headerSize` at construction) cannot
// parse.
//
// Lifecycle. Stream wrappers do NOT take ownership of the wrapped
// `Readable` / `Writable`. The caller retains responsibility for
// closing / disposing the wrapped stream after the wrapper is
// itself closed.

import type { Readable, Writable } from 'node:stream';

import {
  decrypt as lowDecrypt,
  decryptTriple as lowDecryptTriple,
  encrypt as lowEncrypt,
  encryptTriple as lowEncryptTriple,
} from './cipher.js';
import { ITBError } from './errors.js';
import { headerSize, parseChunkLen } from './library.js';
import type { Seed } from './seed.js';
import { Status } from './status.js';

/**
 * Default chunk size — matches `itb.DefaultChunkSize` on the Go
 * side (16 MiB), the size at which ITB's barrier-encoded container
 * layout stays well within the per-chunk pixel cap.
 */
export const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

function asUint8(buf: Uint8Array | Buffer): Uint8Array {
  if (buf instanceof Uint8Array) {
    // Buffer is a Uint8Array subclass; the cast preserves the
    // underlying memory view without an extra copy.
    return buf;
  }
  throw new TypeError('chunk must be a Uint8Array or Buffer');
}

function concatU8(parts: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ──────────────────────────────────────────────────────────────────
// Single Ouroboros — chunked writer.
// ──────────────────────────────────────────────────────────────────

/**
 * Chunked encrypt writer over a Single Ouroboros seed trio. Buffers
 * plaintext until at least `chunkSize` bytes are available, then
 * encrypts and emits one chunk to the wrapped output stream. The
 * trailing partial buffer is flushed as a final chunk on `close`,
 * so the on-the-wire chunk count is `ceil(total / chunkSize)`.
 *
 * Usage:
 *
 *     const enc = new StreamEncryptor(noise, data, start, output);
 *     enc.write(chunkA);
 *     enc.write(chunkB);
 *     enc.close();
 *
 * The wrapped `Writable` is NOT ended when this writer is closed;
 * the caller retains ownership of the stream's lifecycle.
 *
 * @remarks
 * The buffer-and-emit state machine is not safe to invoke
 * concurrently from multiple call sites. Sharing one
 * `StreamEncryptor` across async tasks requires external
 * serialisation.
 */
export class StreamEncryptor {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;

  constructor(
    noise: Seed,
    data: Seed,
    start: Seed,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new RangeError('chunkSize must be positive');
    }
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.output = output;
    this.chunkSize = chunkSize;
  }

  /**
   * Appends `data` to the internal buffer, encrypting and emitting
   * every full `chunkSize`-sized slice that becomes available.
   * Returns the number of bytes consumed (always equal to
   * `data.length` on success).
   */
  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.BadInput, 'write on closed StreamEncryptor');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    while (this.buffered >= this.chunkSize) {
      const merged = concatU8(this.buf, this.buffered);
      const chunk = merged.subarray(0, this.chunkSize);
      const tail = merged.subarray(this.chunkSize);
      const ct = lowEncrypt(this.noise, this.data, this.start, chunk);
      this.output.write(ct);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
    return view.length;
  }

  /**
   * Encrypts and emits any remaining buffered bytes as the final
   * chunk. Idempotent — a second call is a no-op.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const merged = concatU8(this.buf, this.buffered);
      const ct = lowEncrypt(this.noise, this.data, this.start, merged);
      this.output.write(ct);
      this.buf = [];
      this.buffered = 0;
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

// ──────────────────────────────────────────────────────────────────
// Single Ouroboros — chunked reader.
// ──────────────────────────────────────────────────────────────────

/**
 * Chunked decrypt writer: accumulates ciphertext bytes via `feed`
 * until a full chunk (header + body) is available, then decrypts
 * the chunk and writes the plaintext to the output sink. Multiple
 * full chunks in one feed call are processed sequentially.
 *
 * Usage:
 *
 *     const dec = new StreamDecryptor(noise, data, start, output);
 *     dec.feed(ciphertextPart1);
 *     dec.feed(ciphertextPart2);
 *     dec.close();
 *
 * The wrapped `Writable` is NOT ended when this reader is closed;
 * the caller retains ownership of the stream's lifecycle.
 */
export class StreamDecryptor {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly output: Writable;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;
  private readonly headerSize: number;

  constructor(noise: Seed, data: Seed, start: Seed, output: Writable) {
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.output = output;
    // Snapshot at construction so the decryptor uses the same
    // header layout the matching encryptor saw. Changing
    // setNonceBits mid-stream would break decoding anyway.
    this.headerSize = headerSize();
  }

  /**
   * Appends `data` to the internal buffer and drains every
   * complete chunk that has become available, writing decrypted
   * plaintext to the output sink.
   */
  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.BadInput, 'feed on closed StreamDecryptor');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    this.drain();
    return view.length;
  }

  private drain(): void {
    for (;;) {
      if (this.buffered < this.headerSize) {
        return;
      }
      const merged = concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        // Re-pack as one contiguous buffer so the next iteration
        // does not pay the concat cost again.
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const pt = lowDecrypt(this.noise, this.data, this.start, chunk);
      this.output.write(pt);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
  }

  /**
   * Finalises the decryptor. Throws when leftover bytes do not
   * form a complete chunk — streaming ITB ciphertext cannot have
   * a half-chunk tail.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const trailing = this.buffered;
      this.buf = [];
      this.buffered = 0;
      this.closed = true;
      throw new ITBError(
        Status.BadInput,
        `StreamDecryptor: trailing ${trailing} bytes do not form a complete chunk`,
      );
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    // Mark closed without raising on partial input — `Symbol.dispose`
    // is invoked unconditionally by `using` declarations and has no
    // path to surface a half-chunk tail through the ergonomic exit.
    // Callers that need to detect a half-chunk tail must call
    // `close()` explicitly.
    this.closed = true;
  }
}

// ──────────────────────────────────────────────────────────────────
// Triple Ouroboros — chunked writer.
// ──────────────────────────────────────────────────────────────────

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamEncryptor`.
 *
 * @remarks
 * Same threading caveat as `StreamEncryptor` — do not call
 * `setNonceBits` between writes on the same stream.
 */
export class StreamEncryptorTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new RangeError('chunkSize must be positive');
    }
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.output = output;
    this.chunkSize = chunkSize;
  }

  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.BadInput, 'write on closed StreamEncryptorTriple');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    while (this.buffered >= this.chunkSize) {
      const merged = concatU8(this.buf, this.buffered);
      const chunk = merged.subarray(0, this.chunkSize);
      const tail = merged.subarray(this.chunkSize);
      const ct = lowEncryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        chunk,
      );
      this.output.write(ct);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const merged = concatU8(this.buf, this.buffered);
      const ct = lowEncryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        merged,
      );
      this.output.write(ct);
      this.buf = [];
      this.buffered = 0;
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

// ──────────────────────────────────────────────────────────────────
// Triple Ouroboros — chunked reader.
// ──────────────────────────────────────────────────────────────────

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamDecryptor`.
 */
export class StreamDecryptorTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly output: Writable;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;
  private readonly headerSize: number;

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    output: Writable,
  ) {
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.output = output;
    this.headerSize = headerSize();
  }

  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.BadInput, 'feed on closed StreamDecryptorTriple');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    this.drain();
    return view.length;
  }

  private drain(): void {
    for (;;) {
      if (this.buffered < this.headerSize) {
        return;
      }
      const merged = concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const pt = lowDecryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        chunk,
      );
      this.output.write(pt);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
  }

  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const trailing = this.buffered;
      this.buf = [];
      this.buffered = 0;
      this.closed = true;
      throw new ITBError(
        Status.BadInput,
        `StreamDecryptorTriple: trailing ${trailing} bytes do not form a complete chunk`,
      );
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.closed = true;
  }
}

// ──────────────────────────────────────────────────────────────────
// Functional convenience wrappers.
// ──────────────────────────────────────────────────────────────────

async function* iterateReadable(
  input: Readable,
): AsyncGenerator<Uint8Array, void, void> {
  for await (const chunk of input) {
    if (chunk instanceof Uint8Array) {
      yield chunk;
    } else if (typeof chunk === 'string') {
      yield new TextEncoder().encode(chunk);
    } else {
      const kind: string = chunk == null
        ? String(chunk)
        : ((chunk as { constructor?: { name?: string } })?.constructor?.name ?? typeof chunk);
      throw new TypeError(
        `input stream emitted a non-Buffer / non-string chunk (got ${kind}); ` +
          'streams in object-mode are not supported',
      );
    }
  }
}

/**
 * Reads plaintext from `input` until end-of-stream, encrypts in
 * chunks of `chunkSize`, and writes concatenated ITB chunks to
 * `output`. The wrapped streams are NOT closed by the helper —
 * lifecycle ownership stays with the caller.
 *
 * Error semantics on the upstream-failure path. When `input` errors
 * mid-pipeline, the catch arm flushes the buffered partial chunk
 * (via `enc.close()`) before re-raising the original error. The
 * `output` may therefore receive one final partial-plaintext chunk
 * representing data that was already drawn from `input` but did
 * not span the full `chunkSize`. The original error is preserved
 * (encoder-side `close()` is non-throwing); the trailing chunk is
 * a behavioural quirk of the cleanup path, valid ITB ciphertext
 * but representing truncated plaintext on subsequent decrypt.
 */
export async function encryptStream(
  noise: Seed,
  data: Seed,
  start: Seed,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptor(noise, data, start, output, chunkSize);
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Reads concatenated ITB chunks from `input` until end-of-stream
 * and writes the recovered plaintext to `output`. Throws when the
 * trailing input does not form a complete chunk.
 */
export async function decryptStream(
  noise: Seed,
  data: Seed,
  start: Seed,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptor(noise, data, start, output);
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    // Symbol.dispose silently absorbs a trailing-bytes condition by
    // design (the underlying error is what the caller cares about);
    // calling close() in the catch would re-raise the trailing-bytes
    // error and mask the original failure.
    dec[Symbol.dispose]();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `encryptStream`.
 */
export async function encryptStreamTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptorTriple(
    noise, data1, data2, data3, start1, start2, start3, output, chunkSize,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `decryptStream`.
 */
export async function decryptStreamTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptorTriple(
    noise, data1, data2, data3, start1, start2, start3, output,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    // See decryptStream — Symbol.dispose absorbs trailing-bytes;
    // close() would mask the upstream failure.
    dec[Symbol.dispose]();
    throw err;
  }
}
