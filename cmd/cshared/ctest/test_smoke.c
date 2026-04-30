// Smoke test for libitb shared library.
//
// Build & run (from repo root):
//   gcc -Wall -Wextra -O2 -o dist/linux-amd64/test_smoke \
//       cmd/cshared/ctest/test_smoke.c \
//       -Idist/linux-amd64 -Ldist/linux-amd64 -litb -Wl,-rpath,'$ORIGIN'
//   ./dist/linux-amd64/test_smoke
//
// Exits 0 on success, non-zero on any check failure.
//
// The test exercises every public C ABI entry point at least once:
//   - ITB_Version, ITB_HashCount, ITB_HashName, ITB_HashWidth
//   - ITB_NewSeed / ITB_FreeSeed / ITB_SeedWidth / ITB_SeedHashName
//   - ITB_Encrypt / ITB_Decrypt round-trip
//   - ITB_LastError on a bad-hash failure path
//   - ITB_Set/Get for every config knob
//   - ITB_MaxKeyBits, ITB_Channels read-only constants
//   - ITB_ERR_BUFFER_TOO_SMALL feedback path

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "libitb.h"

#define CHECK(cond, msg) do {                                                 \
    if (!(cond)) {                                                            \
        fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, msg);          \
        return 1;                                                             \
    }                                                                         \
} while (0)

#define CHECK_OK(call, msg) do {                                              \
    int _rc = (call);                                                         \
    if (_rc != 0) {                                                           \
        char _err[256] = {0}; size_t _l = 0;                                  \
        ITB_LastError(_err, sizeof(_err), &_l);                               \
        fprintf(stderr, "FAIL %s:%d %s rc=%d err=%s\n",                       \
                __FILE__, __LINE__, msg, _rc, _err);                          \
        return 1;                                                             \
    }                                                                         \
} while (0)

static int test_introspection(void) {
    char buf[64];
    size_t n = 0;

    CHECK_OK(ITB_Version(buf, sizeof(buf), &n), "ITB_Version");
    printf("  version: %s (n=%zu)\n", buf, n);

    int count = ITB_HashCount();
    CHECK(count == 9, "ITB_HashCount must be 9");

    const char *expected[] = {
        "areion256", "areion512", "siphash24", "aescmac",
        "blake2b256", "blake2b512", "blake2s", "blake3", "chacha20",
    };
    int expectedWidths[] = {256, 512, 128, 128, 256, 512, 256, 256, 256};

    for (int i = 0; i < count; i++) {
        CHECK_OK(ITB_HashName(i, buf, sizeof(buf), &n), "ITB_HashName");
        CHECK(strcmp(buf, expected[i]) == 0, "hash name order mismatch");
        int w = ITB_HashWidth(i);
        CHECK(w == expectedWidths[i], "hash width mismatch");
        printf("  [%d] %s width=%d\n", i, buf, w);
    }

    CHECK(ITB_HashWidth(-1) == 0, "HashWidth(-1) must be 0");
    CHECK(ITB_HashWidth(99) == 0, "HashWidth(99) must be 0");
    return 0;
}

static int test_constants(void) {
    int mk = ITB_MaxKeyBits();
    CHECK(mk == 2048, "ITB_MaxKeyBits must be 2048");
    int ch = ITB_Channels();
    CHECK(ch == 8, "ITB_Channels must be 8");
    printf("  MaxKeyBits=%d Channels=%d\n", mk, ch);
    return 0;
}

static int test_bad_hash(void) {
    uintptr_t h = 0;
    int rc = ITB_NewSeed("nonsense-hash-name", 1024, &h);
    CHECK(rc != 0, "NewSeed with bogus name must fail");
    CHECK(h == 0, "handle must remain 0 on failure");

    char err[256] = {0};
    size_t n = 0;
    ITB_LastError(err, sizeof(err), &n);
    printf("  bad-hash err: %s\n", err);
    CHECK(strlen(err) > 0, "ITB_LastError must produce a message");
    return 0;
}

static int run_roundtrip(const char *hashName, int keyBits) {
    uintptr_t ns = 0, ds = 0, ss = 0;
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ns), "NewSeed noise");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ds), "NewSeed data");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ss), "NewSeed start");

    int seedSt = 0;
    int seedW = ITB_SeedWidth(ns, &seedSt);
    CHECK(seedSt == 0 && seedW > 0, "ITB_SeedWidth ok");

    char nameBuf[32] = {0};
    size_t nameLen = 0;
    CHECK_OK(ITB_SeedHashName(ns, nameBuf, sizeof(nameBuf), &nameLen),
             "ITB_SeedHashName");
    CHECK(strcmp(nameBuf, hashName) == 0, "SeedHashName matches input");

    const char *plaintext = "ITB shared-library smoke test plaintext";
    size_t ptlen = strlen(plaintext);

    size_t ctCap = 1 << 20;
    unsigned char *ct = malloc(ctCap);
    CHECK(ct != NULL, "malloc ct");
    size_t ctLen = 0;
    int rc = ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen, ct, ctCap, &ctLen);
    CHECK(rc == 0, "Encrypt rc");
    CHECK(ctLen > 0 && ctLen <= ctCap, "Encrypt length sane");

    unsigned char *pt = malloc(ptlen + 1024); CHECK(pt != NULL, "malloc pt");
    size_t ptOut = 0;
    rc = ITB_Decrypt(ns, ds, ss, ct, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 0, "Decrypt rc");
    CHECK(ptOut == ptlen, "decrypted length matches plaintext");
    CHECK(memcmp(pt, plaintext, ptlen) == 0, "decrypted content matches");

    free(ct);
    free(pt);
    CHECK_OK(ITB_FreeSeed(ns), "FreeSeed noise");
    CHECK_OK(ITB_FreeSeed(ds), "FreeSeed data");
    CHECK_OK(ITB_FreeSeed(ss), "FreeSeed start");
    return 0;
}

static int test_roundtrip_all(void) {
    int count = ITB_HashCount();
    int kb[] = {512, 1024, 2048};
    for (int i = 0; i < count; i++) {
        char name[32]; size_t n = 0;
        ITB_HashName(i, name, sizeof(name), &n);
        for (size_t k = 0; k < sizeof(kb)/sizeof(kb[0]); k++) {
            printf("  roundtrip %s/%dbit\n", name, kb[k]);
            if (run_roundtrip(name, kb[k]) != 0) return 1;
        }
    }
    return 0;
}

static int test_buffer_too_small(void) {
    uintptr_t ns = 0, ds = 0, ss = 0;
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ns), "NewSeed");
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ds), "NewSeed");
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ss), "NewSeed");

    const char *plaintext = "test";
    size_t ptlen = strlen(plaintext);
    unsigned char tiny[4];
    size_t need = 0;
    int rc = ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen, tiny, sizeof(tiny), &need);
    CHECK(rc == 5, "expect ITB_ERR_BUFFER_TOO_SMALL (=5)");
    CHECK(need > sizeof(tiny), "need must report required size");
    printf("  buffer_too_small reported need=%zu\n", need);

    unsigned char *full = malloc(need); CHECK(full != NULL, "malloc full");
    size_t ctLen = 0;
    CHECK_OK(ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen, full, need, &ctLen),
             "retry with sized buffer");
    CHECK(ctLen == need, "ctLen must equal need on retry");

    free(full);
    ITB_FreeSeed(ns); ITB_FreeSeed(ds); ITB_FreeSeed(ss);
    return 0;
}

static int test_config(void) {
    int orig;

    orig = ITB_GetBitSoup();
    CHECK_OK(ITB_SetBitSoup(1), "SetBitSoup");
    CHECK(ITB_GetBitSoup() == 1, "BitSoup readback");
    ITB_SetBitSoup(orig);

    orig = ITB_GetLockSoup();
    CHECK_OK(ITB_SetLockSoup(1), "SetLockSoup");
    CHECK(ITB_GetLockSoup() == 1, "LockSoup readback");
    ITB_SetLockSoup(orig);

    orig = ITB_GetMaxWorkers();
    CHECK_OK(ITB_SetMaxWorkers(4), "SetMaxWorkers");
    CHECK(ITB_GetMaxWorkers() == 4, "MaxWorkers readback");
    ITB_SetMaxWorkers(orig);

    orig = ITB_GetNonceBits();
    CHECK_OK(ITB_SetNonceBits(256), "SetNonceBits valid");
    CHECK(ITB_GetNonceBits() == 256, "NonceBits readback");
    int rc = ITB_SetNonceBits(192);
    CHECK(rc == 4, "SetNonceBits(192) must be ITB_ERR_BAD_INPUT (=4)");
    CHECK(ITB_GetNonceBits() == 256, "NonceBits unchanged after bad input");
    ITB_SetNonceBits(orig);

    orig = ITB_GetBarrierFill();
    CHECK_OK(ITB_SetBarrierFill(8), "SetBarrierFill valid");
    CHECK(ITB_GetBarrierFill() == 8, "BarrierFill readback");
    rc = ITB_SetBarrierFill(7);
    CHECK(rc == 4, "SetBarrierFill(7) must be ITB_ERR_BAD_INPUT");
    ITB_SetBarrierFill(orig);
    return 0;
}

static int run_triple_roundtrip(const char *hashName, int keyBits) {
    uintptr_t h[7] = {0};
    for (int i = 0; i < 7; i++) {
        CHECK_OK(ITB_NewSeed(hashName, keyBits, &h[i]),
                 "Triple NewSeed");
    }

    const char *plaintext = "ITB Triple Ouroboros smoke-test plaintext (7-seed)";
    size_t ptlen = strlen(plaintext);

    size_t ctCap = 1 << 20;
    unsigned char *ct = malloc(ctCap);
    CHECK(ct != NULL, "malloc ct");
    size_t ctLen = 0;
    int rc = ITB_Encrypt3(h[0], h[1], h[2], h[3], h[4], h[5], h[6],
                          (void *)plaintext, ptlen,
                          ct, ctCap, &ctLen);
    CHECK(rc == 0, "Encrypt3 rc");
    CHECK(ctLen > 0 && ctLen <= ctCap, "Encrypt3 length sane");

    unsigned char *pt = malloc(ptlen + 1024); CHECK(pt != NULL, "malloc pt");
    size_t ptOut = 0;
    rc = ITB_Decrypt3(h[0], h[1], h[2], h[3], h[4], h[5], h[6],
                      ct, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 0, "Decrypt3 rc");
    CHECK(ptOut == ptlen, "Triple decrypted length matches plaintext");
    CHECK(memcmp(pt, plaintext, ptlen) == 0, "Triple decrypted content matches");

    free(ct);
    free(pt);
    for (int i = 0; i < 7; i++) ITB_FreeSeed(h[i]);
    return 0;
}

static int test_triple_roundtrip_all(void) {
    int count = ITB_HashCount();
    int kb[] = {512, 1024, 2048};
    for (int i = 0; i < count; i++) {
        char name[32]; size_t n = 0;
        ITB_HashName(i, name, sizeof(name), &n);
        for (size_t k = 0; k < sizeof(kb)/sizeof(kb[0]); k++) {
            printf("  triple-roundtrip %s/%dbit\n", name, kb[k]);
            if (run_triple_roundtrip(name, kb[k]) != 0) return 1;
        }
    }
    return 0;
}

static int test_mac_introspection(void) {
    int count = ITB_MACCount();
    CHECK(count == 3, "ITB_MACCount must be 3");

    const char *expected[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
    char buf[64]; size_t n = 0;
    for (int i = 0; i < count; i++) {
        CHECK_OK(ITB_MACName(i, buf, sizeof(buf), &n), "ITB_MACName");
        CHECK(strcmp(buf, expected[i]) == 0, "MAC name order mismatch");
        CHECK(ITB_MACTagSize(i) == 32, "MAC tag size must be 32");
        CHECK(ITB_MACKeySize(i) == 32, "MAC key size must be 32");
        printf("  [%d] %s tag=%d key=%d minKey=%d\n",
               i, buf, ITB_MACTagSize(i), ITB_MACKeySize(i),
               ITB_MACMinKeyBytes(i));
    }
    return 0;
}

static int run_auth_roundtrip(const char *macName, const char *hashName, int keyBits) {
    unsigned char macKey[32];
    for (int i = 0; i < 32; i++) macKey[i] = (unsigned char)(i ^ 0x55);

    uintptr_t mac = 0;
    CHECK_OK(ITB_NewMAC(macName, macKey, sizeof(macKey), &mac), "NewMAC");

    uintptr_t ns = 0, ds = 0, ss = 0;
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ns), "NewSeed ns");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ds), "NewSeed ds");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ss), "NewSeed ss");

    const char *plaintext = "ITB Authenticated Encryption smoke test plaintext";
    size_t ptlen = strlen(plaintext);

    size_t ctCap = 1 << 20;
    unsigned char *ct = malloc(ctCap); CHECK(ct != NULL, "malloc ct");
    size_t ctLen = 0;
    int rc = ITB_EncryptAuth(ns, ds, ss, mac, (void *)plaintext, ptlen, ct, ctCap, &ctLen);
    CHECK(rc == 0, "EncryptAuth rc");
    CHECK(ctLen > 0, "EncryptAuth ctLen sane");

    unsigned char *pt = malloc(ptlen + 1024); CHECK(pt != NULL, "malloc pt");
    size_t ptOut = 0;
    rc = ITB_DecryptAuth(ns, ds, ss, mac, ct, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 0, "DecryptAuth rc");
    CHECK(ptOut == ptlen, "Auth decrypted len matches plaintext");
    CHECK(memcmp(pt, plaintext, ptlen) == 0, "Auth decrypted content matches");

    // Tamper: flip 256 bytes after the header so at least one
    // payload-region pixel is hit regardless of startPixel offset.
    unsigned char *tampered = malloc(ctLen); CHECK(tampered != NULL, "malloc tampered");
    memcpy(tampered, ct, ctLen);
    /* Default-config header: nonce(16) + width(2) + height(2). */
    size_t tStart = 16 + 4;
    size_t tEnd = tStart + 256;
    if (tEnd > ctLen) tEnd = ctLen;
    for (size_t i = tStart; i < tEnd; i++) tampered[i] ^= 0x01;

    rc = ITB_DecryptAuth(ns, ds, ss, mac, tampered, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 10, "DecryptAuth tampered must be ITB_ERR_MAC_FAILURE (=10)");

    free(ct); free(pt); free(tampered);
    ITB_FreeMAC(mac);
    ITB_FreeSeed(ns); ITB_FreeSeed(ds); ITB_FreeSeed(ss);
    return 0;
}

static int run_auth_triple_roundtrip(const char *macName, const char *hashName, int keyBits) {
    unsigned char macKey[32];
    for (int i = 0; i < 32; i++) macKey[i] = (unsigned char)(i ^ 0xAA);

    uintptr_t mac = 0;
    CHECK_OK(ITB_NewMAC(macName, macKey, sizeof(macKey), &mac), "NewMAC");

    uintptr_t h[7] = {0};
    for (int i = 0; i < 7; i++)
        CHECK_OK(ITB_NewSeed(hashName, keyBits, &h[i]), "NewSeed");

    const char *plaintext = "ITB Triple+Auth smoke test plaintext (7-seed + MAC)";
    size_t ptlen = strlen(plaintext);

    size_t ctCap = 1 << 20;
    unsigned char *ct = malloc(ctCap); CHECK(ct != NULL, "malloc ct");
    size_t ctLen = 0;
    int rc = ITB_EncryptAuth3(h[0], h[1], h[2], h[3], h[4], h[5], h[6],
                              mac, (void *)plaintext, ptlen, ct, ctCap, &ctLen);
    CHECK(rc == 0, "EncryptAuth3 rc");

    unsigned char *pt = malloc(ptlen + 1024); CHECK(pt != NULL, "malloc pt");
    size_t ptOut = 0;
    rc = ITB_DecryptAuth3(h[0], h[1], h[2], h[3], h[4], h[5], h[6],
                          mac, ct, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 0, "DecryptAuth3 rc");
    CHECK(ptOut == ptlen, "Auth3 decrypted len matches");
    CHECK(memcmp(pt, plaintext, ptlen) == 0, "Auth3 decrypted matches");

    unsigned char *tampered = malloc(ctLen); CHECK(tampered != NULL, "malloc tampered");
    memcpy(tampered, ct, ctLen);
    /* Default-config header: nonce(16) + width(2) + height(2). */
    size_t tStart = 16 + 4;
    size_t tEnd = tStart + 256;
    if (tEnd > ctLen) tEnd = ctLen;
    for (size_t i = tStart; i < tEnd; i++) tampered[i] ^= 0x01;
    rc = ITB_DecryptAuth3(h[0], h[1], h[2], h[3], h[4], h[5], h[6],
                          mac, tampered, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 10, "DecryptAuth3 tampered must be MAC_FAILURE");

    free(ct); free(pt); free(tampered);
    ITB_FreeMAC(mac);
    for (int i = 0; i < 7; i++) ITB_FreeSeed(h[i]);
    return 0;
}

static int test_auth_all(void) {
    const char *macs[] = {"kmac256", "hmac-sha256", "hmac-blake3"};
    struct { const char *hash; int width; } hashes[] = {
        {"siphash24", 128}, {"blake3", 256}, {"blake2b512", 512},
    };
    for (size_t mi = 0; mi < 3; mi++) {
        for (size_t hi = 0; hi < 3; hi++) {
            printf("  auth-roundtrip %s/%s\n", macs[mi], hashes[hi].hash);
            if (run_auth_roundtrip(macs[mi], hashes[hi].hash, 1024) != 0) return 1;
            printf("  auth-triple-roundtrip %s/%s\n", macs[mi], hashes[hi].hash);
            if (run_auth_triple_roundtrip(macs[mi], hashes[hi].hash, 1024) != 0) return 1;
        }
    }
    return 0;
}

static int test_parse_chunk_len(void) {
    // Encrypt a small payload, then probe the chunk header through
    // ITB_ParseChunkLen and confirm the reported length matches the
    // ciphertext that ITB_Encrypt actually produced.
    uintptr_t ns = 0, ds = 0, ss = 0;
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ns), "NewSeed");
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ds), "NewSeed");
    CHECK_OK(ITB_NewSeed("blake3", 1024, &ss), "NewSeed");

    const char *plaintext = "stream chunk header parse test";
    size_t ptlen = strlen(plaintext);
    unsigned char ct[1 << 16];
    size_t ctLen = 0;
    CHECK_OK(ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen, ct, sizeof(ct), &ctLen),
             "Encrypt");

    size_t hdrSize = (size_t)ITB_HeaderSize();
    size_t reportedLen = 0;
    int rc = ITB_ParseChunkLen(ct, hdrSize, &reportedLen);
    CHECK(rc == 0, "ITB_ParseChunkLen rc");
    CHECK(reportedLen == ctLen, "ITB_ParseChunkLen reported len matches Encrypt");
    printf("  ParseChunkLen: header(%zu) → chunk(%zu)\n", hdrSize, reportedLen);

    // Short header must be rejected.
    rc = ITB_ParseChunkLen(ct, hdrSize - 1, &reportedLen);
    CHECK(rc == 4, "short header must be ITB_ERR_BAD_INPUT");

    // Repeat the round trip under both non-default nonce
    // configurations and confirm the dynamic ITB_HeaderSize /
    // ITB_ParseChunkLen path tracks the active SetNonceBits
    // override on every supported size (128 / 256 / 512 bits →
    // 20 / 36 / 68-byte headers).
    int origNonce = ITB_GetNonceBits();
    struct { int bits; int header; } nonces[] = {{256, 36}, {512, 68}};
    for (size_t i = 0; i < sizeof(nonces)/sizeof(nonces[0]); i++) {
        CHECK_OK(ITB_SetNonceBits(nonces[i].bits), "SetNonceBits");
        CHECK(ITB_HeaderSize() == nonces[i].header,
              "header size must match expected for nonce config");

        size_t ct2Len = 0;
        unsigned char ct2[1 << 16];
        CHECK_OK(ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen,
                             ct2, sizeof(ct2), &ct2Len),
                 "Encrypt under non-default nonce");
        size_t reported2 = 0;
        rc = ITB_ParseChunkLen(ct2, (size_t)nonces[i].header, &reported2);
        CHECK(rc == 0, "ParseChunkLen under non-default nonce");
        CHECK(reported2 == ct2Len, "ParseChunkLen reported matches Encrypt");
        printf("  ParseChunkLen %d-bit nonce: header(%d) → chunk(%zu)\n",
               nonces[i].bits, nonces[i].header, reported2);

        // Round-trip: decrypt the ciphertext we just produced under
        // this nonce config to be doubly sure the parser-reported
        // length is the right body cut.
        unsigned char pt2[1024];
        size_t pt2Len = 0;
        CHECK_OK(ITB_Decrypt(ns, ds, ss, ct2, ct2Len,
                             pt2, sizeof(pt2), &pt2Len),
                 "Decrypt under non-default nonce");
        CHECK(pt2Len == ptlen, "decrypted length matches plaintext");
        CHECK(memcmp(pt2, plaintext, ptlen) == 0, "decrypted matches plaintext");
    }
    ITB_SetNonceBits(origNonce);

    ITB_FreeSeed(ns); ITB_FreeSeed(ds); ITB_FreeSeed(ss);
    return 0;
}

static int test_double_free(void) {
    uintptr_t h = 0;
    CHECK_OK(ITB_NewSeed("blake3", 1024, &h), "NewSeed");
    CHECK_OK(ITB_FreeSeed(h), "FreeSeed first");
    int rc = ITB_FreeSeed(h);
    CHECK(rc != 0, "second FreeSeed must fail");
    return 0;
}

// run_persistence_roundtrip exercises the full FFI cross-process
// persistence flow for a single (hash, key-bits) pair: encrypt with
// random seeds, snapshot components + hash key, free, reconstruct
// via NewSeedFromComponents, decrypt successfully.
static int run_persistence_roundtrip(const char *hashName, int keyBits) {
    uintptr_t ns = 0, ds = 0, ss = 0;
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ns), "NewSeed noise");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ds), "NewSeed data");
    CHECK_OK(ITB_NewSeed(hashName, keyBits, &ss), "NewSeed start");

    // Snapshot components + hash key for each seed (probe-then-fetch).
    uint64_t ns_comps[32] = {0}, ds_comps[32] = {0}, ss_comps[32] = {0};
    int ns_compsLen = 0, ds_compsLen = 0, ss_compsLen = 0;
    CHECK_OK(ITB_GetSeedComponents(ns, ns_comps, 32, &ns_compsLen),
             "GetSeedComponents noise");
    CHECK_OK(ITB_GetSeedComponents(ds, ds_comps, 32, &ds_compsLen),
             "GetSeedComponents data");
    CHECK_OK(ITB_GetSeedComponents(ss, ss_comps, 32, &ss_compsLen),
             "GetSeedComponents start");
    CHECK(ns_compsLen == keyBits / 64, "components length matches key bits");

    unsigned char ns_key[64] = {0}, ds_key[64] = {0}, ss_key[64] = {0};
    size_t ns_keyLen = 0, ds_keyLen = 0, ss_keyLen = 0;
    CHECK_OK(ITB_GetSeedHashKey(ns, ns_key, 64, &ns_keyLen),
             "GetSeedHashKey noise");
    CHECK_OK(ITB_GetSeedHashKey(ds, ds_key, 64, &ds_keyLen),
             "GetSeedHashKey data");
    CHECK_OK(ITB_GetSeedHashKey(ss, ss_key, 64, &ss_keyLen),
             "GetSeedHashKey start");

    // SipHash-2-4 has no internal fixed key — keyLen must be 0.
    if (strcmp(hashName, "siphash24") == 0) {
        CHECK(ns_keyLen == 0, "siphash24 hash key must be empty");
    } else {
        CHECK(ns_keyLen > 0, "non-siphash24 hash key must be non-empty");
    }

    const char *plaintext = "ITB persistence smoke test plaintext";
    size_t ptlen = strlen(plaintext);

    // Day 1 — encrypt with the original random seeds.
    size_t ctCap = 1 << 20;
    unsigned char *ct = malloc(ctCap); CHECK(ct != NULL, "malloc ct");
    size_t ctLen = 0;
    int rc = ITB_Encrypt(ns, ds, ss, (void *)plaintext, ptlen, ct, ctCap, &ctLen);
    CHECK(rc == 0, "Encrypt rc");

    CHECK_OK(ITB_FreeSeed(ns), "FreeSeed noise (day 1)");
    CHECK_OK(ITB_FreeSeed(ds), "FreeSeed data (day 1)");
    CHECK_OK(ITB_FreeSeed(ss), "FreeSeed start (day 1)");

    // Day 2 — reconstruct from saved material and decrypt.
    uintptr_t ns2 = 0, ds2 = 0, ss2 = 0;
    rc = ITB_NewSeedFromComponents(hashName, ns_comps, ns_compsLen,
                                   ns_key, (int)ns_keyLen, &ns2);
    CHECK(rc == 0, "NewSeedFromComponents noise (day 2)");
    rc = ITB_NewSeedFromComponents(hashName, ds_comps, ds_compsLen,
                                   ds_key, (int)ds_keyLen, &ds2);
    CHECK(rc == 0, "NewSeedFromComponents data (day 2)");
    rc = ITB_NewSeedFromComponents(hashName, ss_comps, ss_compsLen,
                                   ss_key, (int)ss_keyLen, &ss2);
    CHECK(rc == 0, "NewSeedFromComponents start (day 2)");

    unsigned char *pt = malloc(ptlen + 1024); CHECK(pt != NULL, "malloc pt");
    size_t ptOut = 0;
    rc = ITB_Decrypt(ns2, ds2, ss2, ct, ctLen, pt, ptlen + 1024, &ptOut);
    CHECK(rc == 0, "Decrypt rc (restored seeds)");
    CHECK(ptOut == ptlen, "restored decrypted length matches plaintext");
    CHECK(memcmp(pt, plaintext, ptlen) == 0,
          "restored decrypted content matches");

    free(ct);
    free(pt);
    CHECK_OK(ITB_FreeSeed(ns2), "FreeSeed noise (day 2)");
    CHECK_OK(ITB_FreeSeed(ds2), "FreeSeed data (day 2)");
    CHECK_OK(ITB_FreeSeed(ss2), "FreeSeed start (day 2)");
    return 0;
}

static int test_persistence_all(void) {
    int count = ITB_HashCount();
    int kb[] = {512, 1024, 2048};
    for (int i = 0; i < count; i++) {
        char name[32]; size_t n = 0;
        ITB_HashName(i, name, sizeof(name), &n);
        for (size_t k = 0; k < sizeof(kb)/sizeof(kb[0]); k++) {
            int width = ITB_HashWidth(i);
            // Skip combinations where key-bits is not a multiple of
            // the primitive's native hash width (NewSeed would reject).
            if (kb[k] % width != 0) continue;
            printf("  persistence %s/%dbit\n", name, kb[k]);
            if (run_persistence_roundtrip(name, kb[k]) != 0) return 1;
        }
    }
    return 0;
}

static int test_get_seed_buffers_too_small(void) {
    uintptr_t h = 0;
    CHECK_OK(ITB_NewSeed("blake3", 1024, &h), "NewSeed for buf-test");

    // Probe-then-fetch on hash key: cap=0 must report required size.
    size_t keyLen = 0;
    int rc = ITB_GetSeedHashKey(h, NULL, 0, &keyLen);
    CHECK(rc != 0, "ITB_GetSeedHashKey with cap=0 must signal too-small");
    CHECK(keyLen == 32, "blake3 hash key length must be 32 bytes");

    // Probe-then-fetch on components: cap=0 must report required count.
    int compsLen = 0;
    rc = ITB_GetSeedComponents(h, NULL, 0, &compsLen);
    CHECK(rc != 0, "ITB_GetSeedComponents with cap=0 must signal too-small");
    CHECK(compsLen == 16, "1024-bit seed must have 16 uint64 components");

    CHECK_OK(ITB_FreeSeed(h), "FreeSeed");
    return 0;
}

static int test_bad_hash_key_size(void) {
    // Wrong-size hash key for blake3 (expects 32 bytes) must be rejected.
    uint64_t components[8] = {0};
    unsigned char wrongKey[7] = {0};
    uintptr_t h = 0;
    int rc = ITB_NewSeedFromComponents("blake3", components, 8,
                                       wrongKey, 7, &h);
    CHECK(rc != 0, "wrong-size hash key must be rejected");
    CHECK(h == 0, "handle must remain 0 on rejection");
    return 0;
}

int main(void) {
    printf("== introspection ==\n");
    if (test_introspection() != 0) return 1;
    printf("== constants ==\n");
    if (test_constants() != 0) return 1;
    printf("== bad hash ==\n");
    if (test_bad_hash() != 0) return 1;
    printf("== roundtrip all (9 hashes x 3 widths) ==\n");
    if (test_roundtrip_all() != 0) return 1;
    printf("== triple roundtrip all (9 hashes x 3 widths) ==\n");
    if (test_triple_roundtrip_all() != 0) return 1;
    printf("== mac introspection ==\n");
    if (test_mac_introspection() != 0) return 1;
    printf("== auth single+triple all (3 macs x 3 hash widths) ==\n");
    if (test_auth_all() != 0) return 1;
    printf("== parse chunk len ==\n");
    if (test_parse_chunk_len() != 0) return 1;
    printf("== buffer too small ==\n");
    if (test_buffer_too_small() != 0) return 1;
    printf("== config ==\n");
    if (test_config() != 0) return 1;
    printf("== double-free ==\n");
    if (test_double_free() != 0) return 1;
    printf("== persistence (NewSeedFromComponents + GetSeedHashKey + GetSeedComponents) ==\n");
    if (test_persistence_all() != 0) return 1;
    printf("== persistence buffer-too-small ==\n");
    if (test_get_seed_buffers_too_small() != 0) return 1;
    printf("== persistence bad hash key size ==\n");
    if (test_bad_hash_key_size() != 0) return 1;

    printf("\nALL TESTS PASSED\n");
    return 0;
}
