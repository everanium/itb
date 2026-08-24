// URL-query builder for the opts pass-through string.
//
// The builder performs no validation — every key and value is
// rendered into a percent-encoded query string and passed through to
// Go verbatim; libitb rejects unknown keys or bad values with a
// diagnostic surfaced via [ItbException]. Primitive / MAC / cipher /
// palette names are opaque strings.

import 'dart:convert';
import 'dart:typed_data';

/// Builder producing the URL-query-encoded opts string consumed by
/// `Pipeline.create`, `Pipeline.open`, and `registerProfile`. Fluent —
/// every setter mutates and returns the same instance.
class Opts {
  final List<(String, String)> _pairs = [];

  /// Hex-encodes the parallax master override (`pm`).
  Opts withPermMaster(Uint8List master) => withRaw('pm', _hex(master));

  /// Hex-encodes the wrapper master override (`wm`).
  Opts withWrapMaster(Uint8List master) => withRaw('wm', _hex(master));

  Opts withParallax(bool on) => withRaw('withParallax', '$on');

  Opts withWrapper(bool on) => withRaw('withWrapper', '$on');

  Opts withMaxWorkers(int n) => withRaw('maxWorkers', '$n');

  Opts withNonceBits(int n) => withRaw('nonceBits', '$n');

  Opts withBarrierFill(int n) => withRaw('barrierFill', '$n');

  Opts withChunkSize(int n) => withRaw('chunkSize', '$n');

  Opts withKeyBits(int n) => withRaw('keyBits', '$n');

  Opts withParallaxSegmentSize(int n) => withRaw('parallaxSegmentSize', '$n');

  Opts withMacName(String name) => withRaw('macName', name);

  Opts withInnerHash(String name) => withRaw('innerHash', name);

  Opts withOuterCipher(String name) => withRaw('outerCipher', name);

  /// Comma-joins the palette names (`parallaxPalette`).
  Opts withParallaxPalette(List<String> names) =>
      withRaw('parallaxPalette', names.join(','));

  /// Escape hatch appending a raw `key=value` pair. Covers every key
  /// the Go side accepts, including the register-profile grammar
  /// (`mode`, `width`, `innerHashes`, `parallaxOn`, `wrapperOn`, …).
  Opts withRaw(String key, String value) {
    _pairs.add((key, value));
    return this;
  }

  /// Renders the accumulated pairs as a query string.
  String build() => _pairs.map((p) => '${_enc(p.$1)}=${_enc(p.$2)}').join('&');
}

// Minimal percent-encoding: the accepted values are ASCII names,
// decimal integers, true / false, hex, and comma-separated lists, so
// everything outside the URL-safe subset (plus `,`) is escaped
// byte-wise.
final RegExp _safe = RegExp(r'[A-Za-z0-9\-._~,]');

String _enc(String s) {
  final out = StringBuffer();
  for (final b in utf8.encode(s)) {
    final c = String.fromCharCode(b);
    if (_safe.hasMatch(c)) {
      out.write(c);
    } else {
      out.write('%${b.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    }
  }
  return out.toString();
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
