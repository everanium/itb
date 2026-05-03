// Low-level encrypt / decrypt entry points (Single + Triple, plain +
// authenticated). Mirrors bindings/python/itb/_ffi.py top-level
// `encrypt`, `decrypt`, `encrypt_triple`, `decrypt_triple`,
// `encrypt_auth`, `decrypt_auth`, `encrypt_auth_triple`,
// `decrypt_auth_triple`.
//
// Output sizing follows the libitb probe-then-write protocol: the
// first call with `cap=0` returns `Status.BufferTooSmall` and writes
// the required size into `outLen`; the second call with the
// allocated buffer fills it.
//
// All seeds passed to one call must share the same native hash
// width. Mixing widths raises `ITBError(SeedWidthMix)`.

import { errorFromStatus } from './errors.js';
import type { MAC } from './mac.js';
import {
  ITB_Decrypt,
  ITB_Decrypt3,
  ITB_DecryptAuth,
  ITB_DecryptAuth3,
  ITB_Encrypt,
  ITB_Encrypt3,
  ITB_EncryptAuth,
  ITB_EncryptAuth3,
} from './native.js';
import type { Seed } from './seed.js';
import { Status } from './status.js';

type Handle = bigint | number;

type SingleFn = (
  noise: Handle,
  data: Handle,
  start: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type TripleFn = (
  noise: Handle,
  data1: Handle,
  data2: Handle,
  data3: Handle,
  start1: Handle,
  start2: Handle,
  start3: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type AuthSingleFn = (
  noise: Handle,
  data: Handle,
  start: Handle,
  mac: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type AuthTripleFn = (
  noise: Handle,
  data1: Handle,
  data2: Handle,
  data3: Handle,
  start1: Handle,
  start2: Handle,
  start3: Handle,
  mac: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

function ensureBytes(payload: Uint8Array, label: string): void {
  if (!(payload instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }
}

function runSingle(
  fn: SingleFn,
  noise: Seed,
  data: Seed,
  start: Seed,
  payload: Uint8Array,
): Uint8Array {
  const probe: [number | bigint] = [0];
  let rc = fn(noise.handle, data.handle, start.handle, payload, payload.length, null, 0, probe);
  if (rc === Status.Ok) {
    return new Uint8Array(0);
  }
  if (rc !== Status.BufferTooSmall) {
    throw errorFromStatus(rc);
  }
  const need = Number(probe[0]);
  const out = new Uint8Array(need);
  const filled: [number | bigint] = [0];
  rc = fn(noise.handle, data.handle, start.handle, payload, payload.length, out, need, filled);
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(filled[0]));
}

function runTriple(
  fn: TripleFn,
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  payload: Uint8Array,
): Uint8Array {
  const probe: [number | bigint] = [0];
  let rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    payload, payload.length,
    null, 0, probe,
  );
  if (rc === Status.Ok) {
    return new Uint8Array(0);
  }
  if (rc !== Status.BufferTooSmall) {
    throw errorFromStatus(rc);
  }
  const need = Number(probe[0]);
  const out = new Uint8Array(need);
  const filled: [number | bigint] = [0];
  rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    payload, payload.length,
    out, need, filled,
  );
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(filled[0]));
}

function runAuthSingle(
  fn: AuthSingleFn,
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  payload: Uint8Array,
): Uint8Array {
  const probe: [number | bigint] = [0];
  let rc = fn(
    noise.handle, data.handle, start.handle,
    mac.handle,
    payload, payload.length,
    null, 0, probe,
  );
  if (rc === Status.Ok) {
    return new Uint8Array(0);
  }
  if (rc !== Status.BufferTooSmall) {
    throw errorFromStatus(rc);
  }
  const need = Number(probe[0]);
  const out = new Uint8Array(need);
  const filled: [number | bigint] = [0];
  rc = fn(
    noise.handle, data.handle, start.handle,
    mac.handle,
    payload, payload.length,
    out, need, filled,
  );
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(filled[0]));
}

function runAuthTriple(
  fn: AuthTripleFn,
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  mac: MAC,
  payload: Uint8Array,
): Uint8Array {
  const probe: [number | bigint] = [0];
  let rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    mac.handle,
    payload, payload.length,
    null, 0, probe,
  );
  if (rc === Status.Ok) {
    return new Uint8Array(0);
  }
  if (rc !== Status.BufferTooSmall) {
    throw errorFromStatus(rc);
  }
  const need = Number(probe[0]);
  const out = new Uint8Array(need);
  const filled: [number | bigint] = [0];
  rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    mac.handle,
    payload, payload.length,
    out, need, filled,
  );
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(filled[0]));
}

/** Encrypts plaintext under the (noise, data, start) seed trio. */
export function encrypt(
  noise: Seed,
  data: Seed,
  start: Seed,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runSingle(ITB_Encrypt, noise, data, start, plaintext);
}

/** Decrypts ciphertext produced by `encrypt` under the same seed trio. */
export function decrypt(
  noise: Seed,
  data: Seed,
  start: Seed,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runSingle(ITB_Decrypt, noise, data, start, ciphertext);
}

/**
 * Triple-Ouroboros encrypt over seven seeds.
 *
 * Splits plaintext across three interleaved snake payloads. The
 * on-wire ciphertext format is the same shape as `encrypt` — only
 * the internal split / interleave differs. All seven seeds must
 * share the same native hash width and be pairwise distinct
 * handles.
 */
export function encryptTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runTriple(ITB_Encrypt3, noise, data1, data2, data3, start1, start2, start3, plaintext);
}

/** Inverse of `encryptTriple`. */
export function decryptTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runTriple(ITB_Decrypt3, noise, data1, data2, data3, start1, start2, start3, ciphertext);
}

/** Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt. */
export function encryptAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runAuthSingle(ITB_EncryptAuth, noise, data, start, mac, plaintext);
}

/**
 * Authenticated single-Ouroboros decrypt. Raises `ITBError` with
 * code `Status.MacFailure` on tampered ciphertext / wrong MAC key.
 */
export function decryptAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runAuthSingle(ITB_DecryptAuth, noise, data, start, mac, ciphertext);
}

/** Authenticated Triple-Ouroboros encrypt (7 seeds + MAC). */
export function encryptAuthTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: MAC,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runAuthTriple(
    ITB_EncryptAuth3,
    noise, data1, data2, data3, start1, start2, start3, mac, plaintext,
  );
}

/** Authenticated Triple-Ouroboros decrypt. */
export function decryptAuthTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: MAC,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runAuthTriple(
    ITB_DecryptAuth3,
    noise, data1, data2, data3, start1, start2, start3, mac, ciphertext,
  );
}
