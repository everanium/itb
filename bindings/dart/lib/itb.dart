// Thin Dart proxy over the libitb shared library's Triple Pipeline
// surface.
//
// The package wraps the `ITB_Triple_*` C ABI exported by
// `cmd/cshared` (libitb.so / .dylib / .dll) through `dart:ffi` —
// runtime FFI, no build step, no C compiler at install time. Every
// hash-name / MAC-name / cipher-name / profile-name is an opaque
// string passed through to Go for validation; the binding carries no
// ITB construction logic of its own.
//
//   import 'package:itb/itb.dart';
//
//   final sender = Itb.create('singlemsg-triple-mac-v1');
//   final receiver = Itb.open('singlemsg-triple-mac-v1', sender.blob);
//   final wire = sender.encryptMessage(plain);
//   final back = receiver.decryptMessage(wire);

import 'dart:typed_data';

import 'src/pipeline.dart';
import 'src/version.dart' as rt;

export 'src/errors.dart';
export 'src/pipeline.dart';
export 'src/stream.dart';
export 'src/version.dart';

/// Convenience facade over the package's top-level surface.
abstract final class Itb {
  /// Shipped profile identifiers (mirrors the Go `triple` registry).
  /// The list is data for discovery / tooling; every name is still
  /// validated by the Go side at [create] / [open] time. The
  /// blob-only profile exposes no cipher surface.
  static const List<String> profiles = [
    'streaming-aead-triple-mac-v1',
    'streaming-noaead-triple-v1',
    'singlemsg-triple-mac-v1',
    'singlemsg-triple-nomac-v1',
    'streaming-aead-triple-mac-mixed-v1',
    'streaming-noaead-triple-mixed-v1',
    'singlemsg-triple-mac-mixed-v1',
    'singlemsg-triple-nomac-mixed-v1',
    'blob-triple-mac-v1',
  ];

  /// Constructs a fresh [Pipeline] against the named profile.
  static Pipeline create(String profile, [Opts? opts]) =>
      Pipeline.create(profile, opts);

  /// Reconstructs a [Pipeline] from a blob produced by [create] or
  /// [Pipeline.rekey].
  static Pipeline open(String profile, Uint8List blob,
          {Opts? opts, Uint8List? permMaster, Uint8List? wrapMaster}) =>
      Pipeline.open(profile, blob,
          opts: opts, permMaster: permMaster, wrapMaster: wrapMaster);

  /// The shipped hash primitive roster in canonical registry order.
  static List<rt.HashInfo> hashes() => rt.listHashes();

  /// The libitb library version string.
  static String version() => rt.libVersion();

  /// Sets the Go runtime's soft heap limit in bytes; returns the
  /// previous limit. A negative value queries without changing.
  static int setMemoryLimit(int bytes) => rt.setMemoryLimit(bytes);

  /// Sets the Go GC trigger percentage; returns the previous value.
  /// A negative value queries without changing.
  static int setGcPercent(int pct) => rt.setGcPercent(pct);
}
