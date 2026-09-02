// Process-wide Go runtime knobs plus the library version strings.

import 'errors.dart';
import 'ffi_bridge.dart';

/// Binding package version, reported by the eitb CLI.
const String bindingVersion = '0.3.4';

/// Returns the libitb library version string.
String libVersion() {
  final v = readCString(FfiBridge.instance.version);
  if (v.isEmpty) {
    throw ItbException(Status.internal, 'ITB_Version returned nothing');
  }
  return v;
}

/// Sets the Go runtime's soft heap limit in bytes and returns the
/// previous limit. A negative value queries without changing.
int setMemoryLimit(int bytes) => FfiBridge.instance.setMemoryLimit(bytes);

/// Sets the Go GC trigger percentage and returns the previous value.
/// A negative value queries without changing.
int setGcPercent(int pct) => FfiBridge.instance.setGCPercent(pct);

/// Record describing one shipped hash primitive.
typedef HashInfo = ({String name, int widthBits});

/// Enumerates the shipped hash primitive roster in the canonical
/// registry order via `ITB_HashCount` / `ITB_HashName` /
/// `ITB_HashWidth`.
List<HashInfo> listHashes() {
  final bridge = FfiBridge.instance;
  final n = bridge.hashCount();
  final out = <HashInfo>[];
  for (var i = 0; i < n; i++) {
    final name = readCString(
        (outBuf, cap, outLen) => bridge.hashName(i, outBuf, cap, outLen));
    if (name.isEmpty) {
      throw ItbException(Status.internal, 'ITB_HashName($i) returned nothing');
    }
    out.add((name: name, widthBits: bridge.hashWidth(i)));
  }
  return out;
}
