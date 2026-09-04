#!/bin/bash
# Smoke test for cmd/itb3. Verifies build + core round-trip
# invocations over the triple.Load / Save / Rekey / Inspect surface.
# Cobra handles flag-parsing edge cases; the ITB library handles crypto
# correctness. This script exists to catch subprocess wiring / IO
# routing regressions before a release.

set -eu

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO"

BIN="/tmp/itb3-smoke.$$"
CGO_ENABLED=0 go build -o "$BIN" ./cmd/itb3

tmp=$(mktemp -d)
trap 'rm -f "$BIN"; rm -rf "$tmp"' EXIT

# expect_fail <exit-code> <label> <cmd...> — the command must exit
# with exactly <exit-code>; stdout / stderr are discarded.
expect_fail() {
    local want="$1" label="$2"
    shift 2
    set +e
    "$@" >/dev/null 2>&1
    local got=$?
    set -e
    if [ "$got" != "$want" ]; then
        echo "FAIL: $label — expected exit $want, got $got"
        exit 1
    fi
}

echo "=== 1. version / catalog / list subcommands ==="
"$BIN" version  | grep -q "itb3"
"$BIN" catalog  | grep -q "Modes:"
"$BIN" catalog  | grep -q "Profiles:"
"$BIN" hashes   | grep -q "areion512"
"$BIN" macs     | grep -q "kmac256"
"$BIN" ciphers  | grep -q "blake3"
"$BIN" modes    | tr '\n' ' ' | grep -q "mac nomac aead noaead"
"$BIN" profiles | grep -q "singlemsg-triple-mac-v1"

echo "=== 2. roundtrip: genblob → encrypt → decrypt (nomac) + inspect fields ==="
"$BIN" genblob nomac blake3 -o "$tmp/session.blob"
[ -s "$tmp/session.blob" ]
grep -q '"v":2' "$tmp/session.blob"
echo "hello ITB smoke test" > "$tmp/plain.txt"
"$BIN" encrypt "$tmp/session.blob" -i "$tmp/plain.txt" -o "$tmp/cipher.bin"
"$BIN" decrypt "$tmp/session.blob" -i "$tmp/cipher.bin" -o "$tmp/decrypted.txt"
cmp "$tmp/plain.txt" "$tmp/decrypted.txt"
"$BIN" inspect "$tmp/session.blob" > "$tmp/session.inspect"
grep -q "^profile: itb3-nomac-blake3$" "$tmp/session.inspect"
grep -q "^mode: singlemsg-nomac$"      "$tmp/session.inspect"
grep -q "^width: 256$"                 "$tmp/session.inspect"
grep -q "^inner_hash: blake3$"         "$tmp/session.inspect"
grep -q "^key_bits: 1024$"             "$tmp/session.inspect"
grep -q "^mac_name: (none)$"           "$tmp/session.inspect"
grep -q "^wrapper: false$"          "$tmp/session.inspect"
grep -q "^parallax: false$"         "$tmp/session.inspect"
"$BIN" verify "$tmp/session.blob"

echo "=== 3. roundtrip: mac mode + genblob to stdout ==="
"$BIN" genblob mac areion512 -k 1024 -m hmac-blake3 -o "$tmp/mac.blob"
"$BIN" encrypt "$tmp/mac.blob" -i "$tmp/plain.txt" -o "$tmp/mac.cipher"
"$BIN" decrypt "$tmp/mac.blob" -i "$tmp/mac.cipher" -o "$tmp/mac.dec"
cmp "$tmp/plain.txt" "$tmp/mac.dec"
"$BIN" inspect "$tmp/mac.blob" | grep -q "^mac_name: hmac-blake3$"
"$BIN" genblob mac areion512 -m hmac-blake3 > "$tmp/mac-stdout.blob"
"$BIN" verify "$tmp/mac-stdout.blob"
"$BIN" inspect "$tmp/mac-stdout.blob" | grep -q "^mode: singlemsg-mac$"

echo "=== 4. roundtrip: aead mixed256 streaming with 8 MB payload ==="
"$BIN" genblob aead mixed256 -k 1024 -m kmac256 -c 4 -o "$tmp/aead.blob"
dd if=/dev/urandom of="$tmp/big.bin" bs=1M count=8 status=none
"$BIN" encrypt "$tmp/aead.blob" -i "$tmp/big.bin" -o "$tmp/aead.cipher"
"$BIN" decrypt "$tmp/aead.blob" -i "$tmp/aead.cipher" -o "$tmp/aead.dec"
cmp "$tmp/big.bin" "$tmp/aead.dec"
"$BIN" inspect "$tmp/aead.blob" > "$tmp/aead.inspect"
grep -q "^mode: streaming-aead$"      "$tmp/aead.inspect"
grep -q "^width: 256$"                "$tmp/aead.inspect"
grep -q "^mixed_hashes: "             "$tmp/aead.inspect"
grep -q "^chunk_size: 4194304$"       "$tmp/aead.inspect"
[ "$(grep -c "^inner_hash:" "$tmp/aead.inspect")" = "0" ]
# 8 comma-separated slots on the mixed line
[ "$(sed -n 's/^mixed_hashes: //p' "$tmp/aead.inspect" | tr ',' '\n' | wc -l)" = "8" ]

echo "=== 5. rekey + inspect + verify (parallax + wrapper on) ==="
"$BIN" genblob nomac blake3 -p aescmac,siphash24,chacha20 -s 257 -w chacha20 -o "$tmp/rk.blob"
"$BIN" inspect "$tmp/rk.blob" > "$tmp/rk.inspect"
grep -q "^wrapper: true$"                              "$tmp/rk.inspect"
grep -q "^wrapper_cipher: chacha20$"                      "$tmp/rk.inspect"
grep -q "^parallax: true$"                             "$tmp/rk.inspect"
grep -q "^parallax_palette: aescmac,siphash24,chacha20$"  "$tmp/rk.inspect"
grep -q "^parallax_segment_size: 257$"                    "$tmp/rk.inspect"
"$BIN" rekey "$tmp/rk.blob" -p -w -o "$tmp/rk.new"
h_old=$(sha256sum "$tmp/rk.blob" | cut -d' ' -f1)
h_new=$(sha256sum "$tmp/rk.new" | cut -d' ' -f1)
[ "$h_old" != "$h_new" ]
"$BIN" verify "$tmp/rk.new"
# the rekeyed blob keeps the same profile record
"$BIN" inspect "$tmp/rk.new" | grep -v "^blob_bytes:" > "$tmp/rk.new.inspect"
grep -v "^blob_bytes:" "$tmp/rk.inspect" | cmp - "$tmp/rk.new.inspect"

# encrypt with the refreshed blob works
echo "post-rekey" > "$tmp/prk.txt"
"$BIN" encrypt "$tmp/rk.new" -i "$tmp/prk.txt" -o "$tmp/prk.enc"
"$BIN" decrypt "$tmp/rk.new" -i "$tmp/prk.enc" -o "$tmp/prk.dec"
cmp "$tmp/prk.txt" "$tmp/prk.dec"

# a wire produced under the old masters does not decrypt under the new ones
"$BIN" encrypt "$tmp/rk.blob" -i "$tmp/prk.txt" -o "$tmp/prk-old.enc"
if "$BIN" decrypt "$tmp/rk.new" -i "$tmp/prk-old.enc" -o "$tmp/prk-old.dec" 2>/dev/null \
    && cmp -s "$tmp/prk.txt" "$tmp/prk-old.dec"; then
    echo "FAIL: pre-rekey wire decrypted to plaintext under post-rekey masters"
    exit 1
fi

# rekey to stdout
"$BIN" rekey "$tmp/rk.blob" -p -w > "$tmp/rk.stdout"
"$BIN" verify "$tmp/rk.stdout"

echo "=== 6. rekey in-place ==="
h_in=$(sha256sum "$tmp/rk.blob" | cut -d' ' -f1)
"$BIN" rekey "$tmp/rk.blob" -p -w -o "$tmp/rk.blob"
h_out=$(sha256sum "$tmp/rk.blob" | cut -d' ' -f1)
[ "$h_in" != "$h_out" ]
"$BIN" verify "$tmp/rk.blob"

echo "=== 7. stdin/stdout pipe roundtrip ==="
out=$(echo "pipe smoke" | "$BIN" encrypt "$tmp/session.blob" | "$BIN" decrypt "$tmp/session.blob")
[ "$out" = "pipe smoke" ]
out=$(echo "pipe smoke stream" | "$BIN" encrypt "$tmp/aead.blob" | "$BIN" decrypt "$tmp/aead.blob")
[ "$out" = "pipe smoke stream" ]

echo "=== 8. rekey strict-assertion failures (exit 1) ==="
"$BIN" genblob nomac blake3 -o "$tmp/plain.blob"
expect_fail 1 "rekey on both-off blob" "$BIN" rekey "$tmp/plain.blob" -o /dev/null
"$BIN" genblob nomac blake3 -w chacha20 -o "$tmp/wo.blob"
expect_fail 1 "rekey -p on parallax-off blob"    "$BIN" rekey "$tmp/wo.blob" -p -w -o /dev/null
expect_fail 1 "rekey without -w on wrapper-on"   "$BIN" rekey "$tmp/wo.blob" -o /dev/null
expect_fail 1 "rekey without -p on parallax-on"  "$BIN" rekey "$tmp/rk.blob" -w -o /dev/null

echo "=== 9. genblob flag validation (exit 1) ==="
expect_fail 1 "mac mode without -m"      "$BIN" genblob mac areion512
expect_fail 1 "nomac mode with -m"       "$BIN" genblob nomac blake3 -m hmac-blake3
expect_fail 1 "-c on message mode"       "$BIN" genblob nomac blake3 -c 8
expect_fail 1 "keybits 999"              "$BIN" genblob nomac blake3 -k 999
expect_fail 1 "unknown hash"             "$BIN" genblob nomac unknown_hash
expect_fail 1 "unknown mode"             "$BIN" genblob bogus blake3
expect_fail 1 "unknown mac"              "$BIN" genblob mac blake3 -m bogus-mac
expect_fail 1 "unknown wrapper cipher"   "$BIN" genblob nomac blake3 -w bogus
expect_fail 1 "palette below minimum"    "$BIN" genblob nomac blake3 -p aescmac,chacha20
expect_fail 1 "-s without -p"            "$BIN" genblob nomac blake3 -s 257
expect_fail 1 "segment not coprime-504"  "$BIN" genblob nomac blake3 -p aescmac,chacha20,siphash24 -s 256
expect_fail 1 "unknown mixed pseudonym"  "$BIN" genblob nomac mixed999

echo "=== 10. blob rejection: schema version / malformed / missing (exit 2) ==="
printf '{"v":1,"p":"singlemsg-triple-mac-v1","ib":"e30=","wp":true,"ww":true}' > "$tmp/v1.blob"
expect_fail 2 "verify v1 blob"   "$BIN" verify  "$tmp/v1.blob"
expect_fail 2 "inspect v1 blob"  "$BIN" inspect "$tmp/v1.blob"
expect_fail 2 "encrypt v1 blob"  "$BIN" encrypt "$tmp/v1.blob" -i "$tmp/plain.txt"
printf 'not json' > "$tmp/bad.blob"
expect_fail 2 "verify malformed" "$BIN" verify  "$tmp/bad.blob"
expect_fail 2 "verify missing"   "$BIN" verify  "$tmp/does-not-exist.blob"
# a MAC-mode wire tampered in transit fails decryption with the crypto tier
"$BIN" encrypt "$tmp/mac.blob" -i "$tmp/plain.txt" -o "$tmp/tamper.enc"
printf '\xff' | dd of="$tmp/tamper.enc" bs=1 seek=40 conv=notrunc status=none
expect_fail 3 "decrypt tampered MAC wire" "$BIN" decrypt "$tmp/mac.blob" -i "$tmp/tamper.enc" -o /dev/null

echo "=== 11. blob file permissions (POSIX) ==="
if [ "$(uname -s)" = "Linux" ]; then
    [ "$(stat -c '%a' "$tmp/session.blob")" = "600" ]
    [ "$(stat -c '%a' "$tmp/rk.new")" = "600" ]
fi

echo "=== 12. shell completion emit ==="
"$BIN" completion bash       | grep -q "itb3"
"$BIN" completion zsh        | grep -q "itb3"
"$BIN" completion fish       | grep -q "itb3"
"$BIN" completion powershell | grep -q "itb3"

echo "PASS — cmd/itb3 smoke tests"
