package itb

// Red-team attack corpus generator.
//
// Run with:
//   ITB_REDTEAM=1 go test -run TestRedTeamGenerate -v -timeout 30m
//
// Produces attack corpus under tmp/:
//   tmp/plain/<kind>_NNN.txt                    — plaintext (known to attacker — Full KPA)
//   tmp/encrypted/<hash>/<kind>_NNN.bin         — ciphertext (known to attacker)
//   tmp/encrypted/<hash>/<kind>_NNN.pixel       — startPixel hint (known to attacker)
//   tmp/seeds/<hash>/<kind>_NNN.json            — all seeds (for verification only)
//
// Constraints:
//   - Single Ouroboros (noiseSeed, dataSeed, startSeed) — Triple Ouroboros
//     support planned via future mode parameter
//   - 1024-bit keys per seed
//   - SetBarrierFill(N)   — from ITB_BARRIER_FILL env var (default 1,
//                           valid: 1, 2, 4, 8, 16, 32)
//   - SetMaxWorkers(8)    — parallel pixel processing during encryption
//   - Nonce 128 bits default
//   - No MAC / no CCA
//
// Hash variants (10 total, names consistent with BENCH.md):
//
//   128-bit (HashFunc128 → Seed128 → Encrypt128):
//     FNV-1a, MD5, AES-CMAC, SipHash-2-4
//
//   256-bit (HashFunc256 → Seed256 → Encrypt256):
//     ChaCha20, AreionSoEM256, BLAKE2s, BLAKE3
//
//   512-bit (HashFunc512 → Seed512 → Encrypt512):
//     BLAKE2b-512, AreionSoEM512

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// Hash adapter — FNV-1a 128 (not a PRF — linearly invertible)
// ----------------------------------------------------------------------------

var (
	fnvPrime128 *big.Int
	mod128      *big.Int
)

func init() {
	// FNV-1a 128-bit prime: 2^88 + 2^8 + 0x3B = 0x01000000000000000000013B
	fnvPrime128, _ = new(big.Int).SetString("01000000000000000000013B", 16)
	mod128 = new(big.Int).Lsh(big.NewInt(1), 128)
}

func fnv1a128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	state := new(big.Int).SetUint64(seed1)
	state.Lsh(state, 64)
	state.Or(state, new(big.Int).SetUint64(seed0))
	for _, b := range data {
		state.Xor(state, big.NewInt(int64(b)))
		state.Mul(state, fnvPrime128)
		state.Mod(state, mod128)
	}
	buf := make([]byte, 16)
	state.FillBytes(buf)
	hi = binary.BigEndian.Uint64(buf[:8])
	lo = binary.BigEndian.Uint64(buf[8:])
	return
}

// ----------------------------------------------------------------------------
// Hash adapter — MD5 128 (broken PRF — collisions + biases)
// ----------------------------------------------------------------------------

func md5Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	h := md5.New()
	var keyBuf [16]byte
	binary.LittleEndian.PutUint64(keyBuf[:8], seed0)
	binary.LittleEndian.PutUint64(keyBuf[8:], seed1)
	h.Write(keyBuf[:])
	h.Write(data)
	sum := h.Sum(nil)
	lo = binary.LittleEndian.Uint64(sum[:8])
	hi = binary.LittleEndian.Uint64(sum[8:])
	return
}

// ----------------------------------------------------------------------------
// Plaintext generators (deterministic from PRNG seed 42)
// ----------------------------------------------------------------------------

func genHTTP(rng *rand.Rand) []byte {
	methods := []string{"GET", "POST", "PUT", "DELETE"}
	paths := []string{"/api/users", "/api/login", "/health", "/metrics/prometheus", "/v2/auth/token", "/graphql"}
	hosts := []string{"api.example.com", "service.local", "auth.corp.internal", "edge.cdn.net"}

	m := methods[rng.Intn(len(methods))]
	p := paths[rng.Intn(len(paths))]
	h := hosts[rng.Intn(len(hosts))]

	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", m, p, h)
	req += "User-Agent: RedTeam/1.0 (audit-probe)\r\n"
	req += "Accept: application/json,text/html;q=0.9\r\n"
	req += fmt.Sprintf("X-Request-ID: %016x\r\n", rng.Uint64())
	req += fmt.Sprintf("Authorization: Bearer %032x\r\n", rng.Uint64())
	if m == "POST" || m == "PUT" {
		body := fmt.Sprintf(`{"user":"u%d","action":"probe","ts":%d}`, rng.Intn(1_000_000), rng.Int63())
		req += fmt.Sprintf("Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	} else {
		req += "\r\n"
	}
	return []byte(req)
}

func genHTTPLarge(rng *rand.Rand) []byte {
	methods := []string{"POST", "PUT", "PATCH"}
	paths := []string{"/api/v2/users/batch", "/api/v3/documents/upload", "/graphql", "/internal/events/publish", "/ingest/metrics/prometheus", "/sync/differential"}
	hosts := []string{"api.enterprise.example.com", "gateway.internal.corp.net", "edge.fastcdn.dev", "ingress.production.cluster"}
	m := methods[rng.Intn(len(methods))]
	p := paths[rng.Intn(len(paths))]
	h := hosts[rng.Intn(len(hosts))]
	req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", m, p, h)
	req += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0\r\n"
	req += "Accept: application/json,application/vnd.api+json;q=0.9,text/html;q=0.8,*/*;q=0.5\r\n"
	req += "Accept-Language: en-US,en;q=0.9,ru;q=0.8,de;q=0.7\r\n"
	req += "Accept-Encoding: gzip, deflate, br\r\n"
	req += "DNT: 1\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n"
	req += fmt.Sprintf("X-Request-ID: %016x-%016x\r\n", rng.Uint64(), rng.Uint64())
	req += fmt.Sprintf("X-Session-Token: %032x%032x\r\n", rng.Uint64(), rng.Uint64())
	req += fmt.Sprintf("X-Trace-Context: %x-%x-%x-01\r\n", rng.Uint64(), rng.Uint64(), rng.Uint32())
	req += fmt.Sprintf("Authorization: Bearer eyJ%030x.%060x.%040x\r\n", rng.Uint64(), rng.Uint64(), rng.Uint64())
	for i := 0; i < 6+rng.Intn(4); i++ {
		req += fmt.Sprintf("Cookie: session_%d=%032x; path=/; HttpOnly; Secure; SameSite=Lax\r\n", i, rng.Uint64())
	}
	for i := 0; i < 8+rng.Intn(6); i++ {
		req += fmt.Sprintf("X-Custom-%d: %020x-%020x\r\n", i, rng.Uint64(), rng.Uint64())
	}
	type item struct {
		ID          int64    `json:"id"`
		SKU         string   `json:"sku"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Price       float64  `json:"price"`
		Currency    string   `json:"currency"`
		InStock     bool     `json:"in_stock"`
		Tags        []string `json:"tags"`
	}
	type body struct {
		RequestID string            `json:"request_id"`
		Timestamp int64             `json:"timestamp"`
		Source    string            `json:"source"`
		Items     []item            `json:"items"`
		Metadata  map[string]string `json:"metadata"`
	}
	b := body{RequestID: fmt.Sprintf("%x", rng.Uint64()), Timestamp: rng.Int63(), Source: "batch_ingest", Metadata: map[string]string{}}
	nItems := 12 + rng.Intn(25)
	for i := 0; i < nItems; i++ {
		tags := []string{}
		for j := 0; j < 2+rng.Intn(4); j++ {
			tags = append(tags, fmt.Sprintf("tag_%x", rng.Uint32()))
		}
		b.Items = append(b.Items, item{
			ID:          rng.Int63n(10_000_000_000),
			SKU:         fmt.Sprintf("SKU-%08X-%04X", rng.Uint32(), rng.Uint32()&0xFFFF),
			Name:        fmt.Sprintf("Product Name %d (variant %x)", i, rng.Uint32()),
			Description: fmt.Sprintf("Detailed product description for SKU variant %x. Includes technical specifications, material composition, and usage guidelines.", rng.Uint32()),
			Price:       rng.Float64() * 10000,
			Currency:    []string{"USD", "EUR", "GBP", "JPY"}[rng.Intn(4)],
			InStock:     rng.Intn(2) == 0,
			Tags:        tags,
		})
	}
	for k := 0; k < 4+rng.Intn(4); k++ {
		b.Metadata[fmt.Sprintf("attr_%d", k)] = fmt.Sprintf("value_%x_%x", rng.Uint64(), rng.Uint32())
	}
	bodyBytes, _ := json.MarshalIndent(b, "", "  ")
	req += fmt.Sprintf("Content-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\n\r\n", len(bodyBytes))
	req += string(bodyBytes)
	return []byte(req)
}

func genJSON(rng *rand.Rand) []byte {
	type record struct {
		ID    int     `json:"id"`
		Name  string  `json:"name"`
		Value float64 `json:"value"`
		Flag  bool    `json:"flag"`
	}
	type payload struct {
		Timestamp int64    `json:"timestamp"`
		Status    string   `json:"status"`
		Records   []record `json:"records"`
	}
	p := payload{Timestamp: rng.Int63(), Status: "ok"}
	n := 3 + rng.Intn(6)
	for i := 0; i < n; i++ {
		p.Records = append(p.Records, record{
			ID: rng.Intn(100_000), Name: fmt.Sprintf("item_%d_%x", i, rng.Uint32()),
			Value: rng.Float64() * 1000, Flag: rng.Intn(2) == 0,
		})
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return b
}

func genJSONLarge(rng *rand.Rand) []byte {
	type address struct {
		Street     string `json:"street"`
		City       string `json:"city"`
		PostalCode string `json:"postal_code"`
		Country    string `json:"country"`
		Geo        struct {
			Lat float64 `json:"lat"`
			Lng float64 `json:"lng"`
		} `json:"geo"`
	}
	type contact struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	type user struct {
		ID        int64     `json:"id"`
		Username  string    `json:"username"`
		Email     string    `json:"email"`
		CreatedAt int64     `json:"created_at"`
		Active    bool      `json:"active"`
		Address   address   `json:"address"`
		Contacts  []contact `json:"contacts"`
		Tags      []string  `json:"tags"`
		Scores    []float64 `json:"scores"`
	}
	type root struct {
		APIVersion string `json:"api_version"`
		RequestID  string `json:"request_id"`
		Timestamp  int64  `json:"timestamp"`
		Page       struct {
			Current int `json:"current"`
			Total   int `json:"total"`
			Size    int `json:"size"`
		} `json:"page"`
		Users      []user            `json:"users"`
		Metadata   map[string]string `json:"metadata"`
		Statistics map[string]int64  `json:"statistics"`
	}
	r := root{APIVersion: "2.1.0", RequestID: fmt.Sprintf("%x", rng.Uint64()), Timestamp: rng.Int63(), Metadata: map[string]string{}, Statistics: map[string]int64{}}
	r.Page.Current = 1
	r.Page.Size = 25
	r.Page.Total = rng.Intn(1000)
	cities := []string{"London", "Paris", "Tokyo", "New York", "Berlin", "Moscow", "Sydney", "Toronto", "Seoul", "Amsterdam"}
	countries := []string{"GB", "FR", "JP", "US", "DE", "RU", "AU", "CA", "KR", "NL"}
	tagPool := []string{"premium", "verified", "beta", "admin", "vip", "test", "internal", "partner", "trial", "enterprise"}
	nUsers := 10 + rng.Intn(20)
	for i := 0; i < nUsers; i++ {
		u := user{
			ID: rng.Int63n(1_000_000_000), Username: fmt.Sprintf("user_%x_%x", rng.Uint32(), rng.Uint32()&0xFFFF),
			Email: fmt.Sprintf("user%d_%x@example.com", i, rng.Uint32()), CreatedAt: rng.Int63(), Active: rng.Intn(2) == 0,
		}
		cIdx := rng.Intn(len(cities))
		u.Address.Street = fmt.Sprintf("%d %s Avenue", 1+rng.Intn(9999), []string{"North", "South", "East", "West", "Central"}[rng.Intn(5)])
		u.Address.City = cities[cIdx]
		u.Address.Country = countries[cIdx]
		u.Address.PostalCode = fmt.Sprintf("%05d", rng.Intn(100000))
		u.Address.Geo.Lat = -90 + rng.Float64()*180
		u.Address.Geo.Lng = -180 + rng.Float64()*360
		for j := 0; j < 2+rng.Intn(3); j++ {
			u.Contacts = append(u.Contacts, contact{Type: []string{"phone", "mobile", "work", "fax", "telegram"}[rng.Intn(5)], Value: fmt.Sprintf("+%d-%04d-%06d", rng.Intn(99), rng.Intn(9999), rng.Intn(999999))})
		}
		for j := 0; j < 2+rng.Intn(4); j++ {
			u.Tags = append(u.Tags, tagPool[rng.Intn(len(tagPool))])
		}
		for j := 0; j < 3+rng.Intn(5); j++ {
			u.Scores = append(u.Scores, rng.Float64()*100)
		}
		r.Users = append(r.Users, u)
	}
	for k := 0; k < 5+rng.Intn(5); k++ {
		r.Metadata[fmt.Sprintf("field_%d", k)] = fmt.Sprintf("meta_value_%x_%x", rng.Uint64(), rng.Uint32())
		r.Statistics[fmt.Sprintf("counter_%d", k)] = rng.Int63n(1_000_000)
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return b
}

func genJSONHuge(rng *rand.Rand) []byte {
	type record struct {
		ID          int64              `json:"id"`
		SKU         string             `json:"sku"`
		Name        string             `json:"name"`
		Description string             `json:"description"`
		Category    string             `json:"category"`
		Tags        []string           `json:"tags"`
		Price       float64            `json:"price"`
		Currency    string             `json:"currency"`
		InStock     bool               `json:"in_stock"`
		Supplier    map[string]string  `json:"supplier"`
		Dimensions  map[string]float64 `json:"dimensions"`
	}
	type root struct {
		Version  string            `json:"version"`
		Records  []record          `json:"records"`
		Metadata map[string]string `json:"metadata"`
	}
	r := root{Version: "3.1", Metadata: map[string]string{}}
	categories := []string{"electronics", "tools", "apparel", "furniture", "food", "automotive", "books", "garden"}
	countries := []string{"US", "DE", "JP", "CN", "IT", "FR", "UK", "KR", "CA", "AU"}
	target := 100_000 + rng.Intn(50_000)
	for {
		tags := []string{}
		for j := 0; j < 3+rng.Intn(5); j++ {
			tags = append(tags, fmt.Sprintf("tag_%s_%x", categories[rng.Intn(len(categories))], rng.Uint32()))
		}
		rec := record{
			ID: rng.Int63n(10_000_000_000), SKU: fmt.Sprintf("SKU-%08X-%04X-%04X", rng.Uint32(), rng.Uint32()&0xFFFF, rng.Uint32()&0xFFFF),
			Name:        fmt.Sprintf("Product %x variant %x rev %d", rng.Uint32(), rng.Uint32(), rng.Intn(100)),
			Description: fmt.Sprintf("Extended product description for entry %x. Technical specifications, materials composition, usage guidelines, warranty information, and compliance certifications. Tested at %d°C, certified to %x standard.", rng.Uint32(), rng.Intn(100), rng.Uint32()),
			Category:    categories[rng.Intn(len(categories))], Tags: tags,
			Price: rng.Float64() * 10000, Currency: []string{"USD", "EUR", "GBP", "JPY"}[rng.Intn(4)],
			InStock:    rng.Intn(2) == 0,
			Supplier:   map[string]string{"name": fmt.Sprintf("Supplier_%x", rng.Uint32()), "country": countries[rng.Intn(len(countries))], "contact": fmt.Sprintf("contact_%x@supplier.corp", rng.Uint32())},
			Dimensions: map[string]float64{"length": rng.Float64() * 100, "width": rng.Float64() * 100, "height": rng.Float64() * 100, "weight": rng.Float64() * 50},
		}
		r.Records = append(r.Records, rec)
		b, _ := json.MarshalIndent(r, "", "  ")
		if len(b) >= target {
			return b
		}
	}
}

func genHTMLHuge(rng *rand.Rand) []byte {
	target := 100_000 + rng.Intn(50_000)
	var buf []byte
	buf = append(buf, []byte(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Product Catalog — Enterprise Listing</title>
<meta name="description" content="Complete product catalog with pricing, inventory, and specifications.">
<link rel="stylesheet" href="/assets/css/main.css"><script src="/assets/js/analytics.js" async></script>
</head><body>
<header class="site-header"><nav class="main-nav"><ul><li><a href="/home">Home</a></li><li><a href="/catalog">Catalog</a></li><li><a href="/about">About</a></li></ul></nav></header>
<main class="content">
`)...)
	sections := []string{"Electronics", "Tools", "Apparel", "Furniture", "Food", "Automotive", "Books"}
	for _, sec := range sections {
		buf = append(buf, []byte(fmt.Sprintf(`  <section class="category" id="cat-%s">
    <h2>%s</h2>
    <table class="product-table">
      <thead><tr><th>SKU</th><th>Name</th><th>Price</th><th>Stock</th><th>Description</th></tr></thead>
      <tbody>
`, sec, sec))...)
		for r := 0; r < 100; r++ {
			row := fmt.Sprintf(`        <tr><td>SKU-%08X</td><td>Product %x %s</td><td>$%.2f</td><td>%d</td><td>Detailed specification for product id %x including certifications, materials, and usage guidelines. Compliance with international standards tested at laboratory %x.</td></tr>`+"\n",
				rng.Uint32(), rng.Uint32(), sec, rng.Float64()*1000, rng.Intn(1000), rng.Uint32(), rng.Uint32())
			buf = append(buf, []byte(row)...)
			if len(buf) >= target {
				buf = append(buf, []byte(`      </tbody></table></section></main>
<footer class="site-footer"><p>&copy; 2026 Enterprise Corp. All rights reserved.</p></footer>
</body></html>`)...)
				return buf
			}
		}
		buf = append(buf, []byte("      </tbody></table></section>\n")...)
	}
	for len(buf) < target {
		buf = append(buf, []byte(fmt.Sprintf(`  <aside class="sidebar-%x"><h3>Related Links %x</h3><ul>
`, rng.Uint32(), rng.Uint32()))...)
		for i := 0; i < 20; i++ {
			buf = append(buf, []byte(fmt.Sprintf(`      <li><a href="/page-%x" title="Page %d">Link entry %x with descriptive text about item %x</a></li>`+"\n", rng.Uint32(), i, rng.Uint32(), rng.Uint32()))...)
			if len(buf) >= target {
				break
			}
		}
		buf = append(buf, []byte("    </ul></aside>\n")...)
	}
	buf = append(buf, []byte(`</main><footer class="site-footer"><p>&copy; 2026 Enterprise Corp. All rights reserved.</p></footer></body></html>`)...)
	return buf
}

// genHTMLGiant produces ~1 MB HTML (close enough for KL signal headroom).
// With ~150k data pixels × 8 channels = ~1.2M observations per candidate,
// finite-sample KL bias drops to ~0.0001 nats vs. ~0.0006 at html_huge size —
// structural bias, if any, would separate from the noise floor more cleanly.
func genHTMLGiant(rng *rand.Rand) []byte {
	const target = 1024 * 1024
	var buf []byte
	buf = append(buf, []byte(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enterprise Data Catalog — Complete Product Inventory</title>
<meta name="description" content="Comprehensive product catalog with full specifications, pricing, inventory, and supplier information.">
<meta name="keywords" content="catalog, inventory, products, specifications, pricing, wholesale">
<link rel="stylesheet" href="/assets/css/main.css">
<link rel="stylesheet" href="/assets/css/catalog.css">
<link rel="stylesheet" href="/assets/css/print.css" media="print">
<script src="/assets/js/analytics.js" async></script>
<script src="/assets/js/catalog.js" defer></script>
</head><body class="catalog-page theme-light">
<header class="site-header" role="banner">
  <nav class="main-nav" aria-label="Primary"><ul>
    <li><a href="/home">Home</a></li>
    <li><a href="/catalog">Catalog</a></li>
    <li><a href="/inventory">Inventory</a></li>
    <li><a href="/reports">Reports</a></li>
    <li><a href="/suppliers">Suppliers</a></li>
    <li><a href="/about">About</a></li>
  </ul></nav>
</header>
<main class="content" role="main">
`)...)
	sections := []string{
		"Electronics", "Tools", "Apparel", "Furniture", "Food & Beverages",
		"Automotive", "Books & Media", "Garden & Outdoor", "Sports & Recreation",
		"Home Improvement", "Office Supplies", "Health & Beauty",
	}
	for len(buf) < target {
		sec := sections[rng.Intn(len(sections))]
		buf = append(buf, []byte(fmt.Sprintf(`  <section class="category" id="cat-%s-%x">
    <h2>%s <span class="subtitle">(revision %d)</span></h2>
    <p class="description">Full listing of %s products with specifications, pricing, and inventory status.</p>
    <table class="product-table" data-section="%s">
      <thead><tr>
        <th>SKU</th><th>Name</th><th>Price (USD)</th><th>Stock</th>
        <th>Supplier</th><th>Last Updated</th><th>Description</th>
      </tr></thead>
      <tbody>
`, sec, rng.Uint32(), sec, rng.Intn(20), sec, sec))...)
		for r := 0; r < 80; r++ {
			row := fmt.Sprintf(`        <tr data-row="%x"><td>SKU-%08X-%04X</td><td>Product %x variant %s</td><td>$%.2f</td><td>%d</td><td>Supplier-%x</td><td>2026-%02d-%02d %02d:%02d</td><td>Detailed specification for product id %x including certifications, materials composition, usage guidelines, warranty information, and compliance with international standards. Tested at laboratory %x under condition profile %x-%x.</td></tr>`+"\n",
				rng.Uint32(), rng.Uint32(), rng.Uint32()&0xFFFF, rng.Uint32(), sec,
				rng.Float64()*5000, rng.Intn(10000), rng.Uint32(),
				1+rng.Intn(12), 1+rng.Intn(28), rng.Intn(24), rng.Intn(60),
				rng.Uint32(), rng.Uint32(), rng.Uint32(), rng.Uint32())
			buf = append(buf, []byte(row)...)
			if len(buf) >= target {
				break
			}
		}
		buf = append(buf, []byte("      </tbody></table></section>\n")...)
		if len(buf) >= target {
			break
		}
		// Interleave sidebar blocks to vary the byte profile
		buf = append(buf, []byte(fmt.Sprintf(`  <aside class="sidebar sidebar-%x" aria-label="Related">
    <h3>Related Links</h3>
    <ul class="related">
`, rng.Uint32()))...)
		for i := 0; i < 30; i++ {
			buf = append(buf, []byte(fmt.Sprintf(`      <li><a href="/item/%x" title="Item %d"><span class="tag">%s</span> Related entry %x (ref %x)</a></li>`+"\n",
				rng.Uint32(), i, sections[rng.Intn(len(sections))], rng.Uint32(), rng.Uint32()))...)
			if len(buf) >= target {
				break
			}
		}
		buf = append(buf, []byte("    </ul></aside>\n")...)
	}
	buf = append(buf, []byte(`</main>
<footer class="site-footer" role="contentinfo">
  <p>&copy; 2026 Enterprise Corp. All rights reserved. Catalog revision 2026.04.</p>
  <p><small>Generated for red-team KL analysis — giant sample for tight finite-sample KL floor.</small></p>
</footer>
</body></html>`)...)
	return buf
}

func genRawText(rng *rand.Rand, length int) []byte {
	corpus := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. "
	buf := make([]byte, 0, length)
	for len(buf) < length {
		start := rng.Intn(len(corpus) - 30)
		end := start + 20 + rng.Intn(len(corpus)-start-20)
		if end > len(corpus) {
			end = len(corpus)
		}
		buf = append(buf, corpus[start:end]...)
	}
	return buf[:length]
}

// ----------------------------------------------------------------------------
// Unified hash spec with width-agnostic encrypt closure
// ----------------------------------------------------------------------------

// encryptResult holds the output of a single encryption attempt across any hash
// width and either Ouroboros mode. Each of StartPixels / DataSeeds / StartSeeds
// is length 1 in Single mode and length 3 in Triple mode; StartPixels[i] is
// local to the i-th third in Triple mode (i.e., in [0, thirdSize_i)).
type encryptResult struct {
	Ciphertext  []byte
	Width       int
	Height      int
	TotalPixels int
	Nonce       []byte
	NoiseSeed   []uint64
	StartPixels []int
	DataSeeds   [][]uint64
	StartSeeds  [][]uint64
}

// hashSpec describes one hash primitive entry for the red-team corpus. Abstracted over
// the three ITB widths (128/256/512) and over Ouroboros mode (single vs triple).
type hashSpec struct {
	displayName string // BENCH.md name: "FNV-1a", "SipHash-2-4", "BLAKE2b-512", etc.
	dirname     string // filesystem-safe: "fnv1a", "siphash24", "blake2b"
	width       int    // hash output bits (128, 256, or 512)
	encrypt     func(plaintext []byte) (*encryptResult, error)
}

// encrypt128Closure builds an encrypt function for a 128-bit hash.
func encrypt128Closure(hf HashFunc128, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed128(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds, err := NewSeed128(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("data seed: %w", err)
		}
		ss, err := NewSeed128(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("start seed: %w", err)
		}
		ct, err := Encrypt128(ns, ds, ss, plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		dec, err := Decrypt128(ns, ds, ss, ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		nonceSize := currentNonceSize()
		nonce := ct[:nonceSize]
		w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
		h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
		totalPixels := w * h
		sp := ss.deriveStartPixel(nonce, totalPixels)
		return &encryptResult{
			Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
			Nonce:       nonce,
			NoiseSeed:   append([]uint64{}, ns.Components...),
			StartPixels: []int{sp},
			DataSeeds:   [][]uint64{append([]uint64{}, ds.Components...)},
			StartSeeds:  [][]uint64{append([]uint64{}, ss.Components...)},
		}, nil
	}
}

// encrypt256Closure builds an encrypt function for a 256-bit hash.
func encrypt256Closure(hf HashFunc256, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed256(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds, err := NewSeed256(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("data seed: %w", err)
		}
		ss, err := NewSeed256(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("start seed: %w", err)
		}
		ct, err := Encrypt256(ns, ds, ss, plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		dec, err := Decrypt256(ns, ds, ss, ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		nonceSize := currentNonceSize()
		nonce := ct[:nonceSize]
		w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
		h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
		totalPixels := w * h
		sp := ss.deriveStartPixel(nonce, totalPixels)
		return &encryptResult{
			Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
			Nonce:       nonce,
			NoiseSeed:   append([]uint64{}, ns.Components...),
			StartPixels: []int{sp},
			DataSeeds:   [][]uint64{append([]uint64{}, ds.Components...)},
			StartSeeds:  [][]uint64{append([]uint64{}, ss.Components...)},
		}, nil
	}
}

// encrypt512Closure builds an encrypt function for a 512-bit hash.
func encrypt512Closure(hf HashFunc512, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed512(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds, err := NewSeed512(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("data seed: %w", err)
		}
		ss, err := NewSeed512(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("start seed: %w", err)
		}
		ct, err := Encrypt512(ns, ds, ss, plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		dec, err := Decrypt512(ns, ds, ss, ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		nonceSize := currentNonceSize()
		nonce := ct[:nonceSize]
		w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
		h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
		totalPixels := w * h
		sp := ss.deriveStartPixel(nonce, totalPixels)
		return &encryptResult{
			Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
			Nonce:       nonce,
			NoiseSeed:   append([]uint64{}, ns.Components...),
			StartPixels: []int{sp},
			DataSeeds:   [][]uint64{append([]uint64{}, ds.Components...)},
			StartSeeds:  [][]uint64{append([]uint64{}, ss.Components...)},
		}, nil
	}
}

// ----------------------------------------------------------------------------
// Triple Ouroboros closures — 7 seeds per encryption (1 noise + 3 data + 3 start)
// ----------------------------------------------------------------------------

// encrypt3x128Closure builds a Triple-Ouroboros encrypt function for a 128-bit hash.
func encrypt3x128Closure(hf HashFunc128, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed128(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds := [3]*Seed128{}
		ss := [3]*Seed128{}
		for i := 0; i < 3; i++ {
			ds[i], err = NewSeed128(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("data seed %d: %w", i, err)
			}
			ss[i], err = NewSeed128(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("start seed %d: %w", i, err)
			}
		}
		ct, err := Encrypt3x128(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt3x: %w", err)
		}
		dec, err := Decrypt3x128(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt3x verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		return assembleTripleResult128(ct, ns, ds, ss), nil
	}
}

// encrypt3x256Closure builds a Triple-Ouroboros encrypt function for a 256-bit hash.
func encrypt3x256Closure(hf HashFunc256, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed256(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds := [3]*Seed256{}
		ss := [3]*Seed256{}
		for i := 0; i < 3; i++ {
			ds[i], err = NewSeed256(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("data seed %d: %w", i, err)
			}
			ss[i], err = NewSeed256(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("start seed %d: %w", i, err)
			}
		}
		ct, err := Encrypt3x256(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt3x: %w", err)
		}
		dec, err := Decrypt3x256(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt3x verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		return assembleTripleResult256(ct, ns, ds, ss), nil
	}
}

// encrypt3x512Closure builds a Triple-Ouroboros encrypt function for a 512-bit hash.
func encrypt3x512Closure(hf HashFunc512, keyBits int) func([]byte) (*encryptResult, error) {
	return func(plaintext []byte) (*encryptResult, error) {
		ns, err := NewSeed512(keyBits, hf)
		if err != nil {
			return nil, fmt.Errorf("noise seed: %w", err)
		}
		ds := [3]*Seed512{}
		ss := [3]*Seed512{}
		for i := 0; i < 3; i++ {
			ds[i], err = NewSeed512(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("data seed %d: %w", i, err)
			}
			ss[i], err = NewSeed512(keyBits, hf)
			if err != nil {
				return nil, fmt.Errorf("start seed %d: %w", i, err)
			}
		}
		ct, err := Encrypt3x512(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], plaintext)
		if err != nil {
			return nil, fmt.Errorf("encrypt3x: %w", err)
		}
		dec, err := Decrypt3x512(ns, ds[0], ds[1], ds[2], ss[0], ss[1], ss[2], ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt3x verify: %w", err)
		}
		if string(dec) != string(plaintext) {
			return nil, fmt.Errorf("round-trip mismatch: %d vs %d bytes", len(plaintext), len(dec))
		}
		return assembleTripleResult512(ct, ns, ds, ss), nil
	}
}

// assembleTripleResult128 extracts container dims and derives per-third startPixels
// for a 128-bit Triple ciphertext. Each third is sized (totalPixels / 3) for thirds 0
// and 1, with third 2 getting any remainder — mirroring Encrypt3x128's partition.
func assembleTripleResult128(ct []byte, ns *Seed128, ds, ss [3]*Seed128) *encryptResult {
	nonceSize := currentNonceSize()
	nonce := ct[:nonceSize]
	w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
	h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
	totalPixels := w * h
	third := totalPixels / 3
	thirdSizes := [3]int{third, third, totalPixels - 2*third}
	sps := make([]int, 3)
	dsOut := make([][]uint64, 3)
	ssOut := make([][]uint64, 3)
	for i := 0; i < 3; i++ {
		sps[i] = ss[i].deriveStartPixel(nonce, thirdSizes[i])
		dsOut[i] = append([]uint64{}, ds[i].Components...)
		ssOut[i] = append([]uint64{}, ss[i].Components...)
	}
	return &encryptResult{
		Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
		Nonce:       nonce,
		NoiseSeed:   append([]uint64{}, ns.Components...),
		StartPixels: sps,
		DataSeeds:   dsOut,
		StartSeeds:  ssOut,
	}
}

func assembleTripleResult256(ct []byte, ns *Seed256, ds, ss [3]*Seed256) *encryptResult {
	nonceSize := currentNonceSize()
	nonce := ct[:nonceSize]
	w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
	h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
	totalPixels := w * h
	third := totalPixels / 3
	thirdSizes := [3]int{third, third, totalPixels - 2*third}
	sps := make([]int, 3)
	dsOut := make([][]uint64, 3)
	ssOut := make([][]uint64, 3)
	for i := 0; i < 3; i++ {
		sps[i] = ss[i].deriveStartPixel(nonce, thirdSizes[i])
		dsOut[i] = append([]uint64{}, ds[i].Components...)
		ssOut[i] = append([]uint64{}, ss[i].Components...)
	}
	return &encryptResult{
		Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
		Nonce:       nonce,
		NoiseSeed:   append([]uint64{}, ns.Components...),
		StartPixels: sps,
		DataSeeds:   dsOut,
		StartSeeds:  ssOut,
	}
}

func assembleTripleResult512(ct []byte, ns *Seed512, ds, ss [3]*Seed512) *encryptResult {
	nonceSize := currentNonceSize()
	nonce := ct[:nonceSize]
	w := int(binary.BigEndian.Uint16(ct[nonceSize:]))
	h := int(binary.BigEndian.Uint16(ct[nonceSize+2:]))
	totalPixels := w * h
	third := totalPixels / 3
	thirdSizes := [3]int{third, third, totalPixels - 2*third}
	sps := make([]int, 3)
	dsOut := make([][]uint64, 3)
	ssOut := make([][]uint64, 3)
	for i := 0; i < 3; i++ {
		sps[i] = ss[i].deriveStartPixel(nonce, thirdSizes[i])
		dsOut[i] = append([]uint64{}, ds[i].Components...)
		ssOut[i] = append([]uint64{}, ss[i].Components...)
	}
	return &encryptResult{
		Ciphertext: ct, Width: w, Height: h, TotalPixels: totalPixels,
		Nonce:       nonce,
		NoiseSeed:   append([]uint64{}, ns.Components...),
		StartPixels: sps,
		DataSeeds:   dsOut,
		StartSeeds:  ssOut,
	}
}

// buildHashSpecs constructs the 10 hash variant specs for the red-team suite.
// Key size is 1024 bits for all variants (standard ITB security level).
// Hash functions that carry fixed random keys (AES-CMAC, BLAKE2s, BLAKE3, BLAKE2b,
// AreionSoEM) are built once here and reused across all samples.
func buildHashSpecs(keyBits int, triple bool) []hashSpec {
	aesCMAC := makeAESHash128()
	chacha20 := makeChaCha20Hash256()
	areion256 := makeAreionSoEM256()
	blake2s := makeBlake2sHash256()
	blake3 := makeBlake3Hash256()
	blake2b512 := makeBlake2bHash512()
	areion512 := makeAreionSoEM512()

	if triple {
		return []hashSpec{
			{displayName: "FNV-1a", dirname: "fnv1a", width: 128, encrypt: encrypt3x128Closure(fnv1a128, keyBits)},
			{displayName: "MD5", dirname: "md5", width: 128, encrypt: encrypt3x128Closure(md5Hash128, keyBits)},
			{displayName: "AES-CMAC", dirname: "aescmac", width: 128, encrypt: encrypt3x128Closure(aesCMAC, keyBits)},
			{displayName: "SipHash-2-4", dirname: "siphash24", width: 128, encrypt: encrypt3x128Closure(sipHash128, keyBits)},
			{displayName: "ChaCha20", dirname: "chacha20", width: 256, encrypt: encrypt3x256Closure(chacha20, keyBits)},
			{displayName: "AreionSoEM256", dirname: "areion256", width: 256, encrypt: encrypt3x256Closure(areion256, keyBits)},
			{displayName: "BLAKE2s", dirname: "blake2s", width: 256, encrypt: encrypt3x256Closure(blake2s, keyBits)},
			{displayName: "BLAKE3", dirname: "blake3", width: 256, encrypt: encrypt3x256Closure(blake3, keyBits)},
			{displayName: "BLAKE2b-512", dirname: "blake2b", width: 512, encrypt: encrypt3x512Closure(blake2b512, keyBits)},
			{displayName: "AreionSoEM512", dirname: "areion512", width: 512, encrypt: encrypt3x512Closure(areion512, keyBits)},
		}
	}
	return []hashSpec{
		{displayName: "FNV-1a", dirname: "fnv1a", width: 128, encrypt: encrypt128Closure(fnv1a128, keyBits)},
		{displayName: "MD5", dirname: "md5", width: 128, encrypt: encrypt128Closure(md5Hash128, keyBits)},
		{displayName: "AES-CMAC", dirname: "aescmac", width: 128, encrypt: encrypt128Closure(aesCMAC, keyBits)},
		{displayName: "SipHash-2-4", dirname: "siphash24", width: 128, encrypt: encrypt128Closure(sipHash128, keyBits)},
		{displayName: "ChaCha20", dirname: "chacha20", width: 256, encrypt: encrypt256Closure(chacha20, keyBits)},
		{displayName: "AreionSoEM256", dirname: "areion256", width: 256, encrypt: encrypt256Closure(areion256, keyBits)},
		{displayName: "BLAKE2s", dirname: "blake2s", width: 256, encrypt: encrypt256Closure(blake2s, keyBits)},
		{displayName: "BLAKE3", dirname: "blake3", width: 256, encrypt: encrypt256Closure(blake3, keyBits)},
		{displayName: "BLAKE2b-512", dirname: "blake2b", width: 512, encrypt: encrypt512Closure(blake2b512, keyBits)},
		{displayName: "AreionSoEM512", dirname: "areion512", width: 512, encrypt: encrypt512Closure(areion512, keyBits)},
	}
}

// ----------------------------------------------------------------------------
// Plaintext kind registry
// ----------------------------------------------------------------------------

type kindSpec struct {
	name  string
	count int
	gen   func(rng *rand.Rand, idx int) []byte
}

var kinds = []kindSpec{
	{"http", 10, func(rng *rand.Rand, _ int) []byte { return genHTTP(rng) }},
	{"json", 10, func(rng *rand.Rand, _ int) []byte { return genJSON(rng) }},
	{"text_small", 10, func(rng *rand.Rand, _ int) []byte { return genRawText(rng, 200+rng.Intn(200)) }},
	{"text_large", 30, func(rng *rand.Rand, _ int) []byte { return genRawText(rng, 20_000+rng.Intn(4_000)) }},
	{"http_large", 30, func(rng *rand.Rand, _ int) []byte { return genHTTPLarge(rng) }},
	{"json_large", 30, func(rng *rand.Rand, _ int) []byte { return genJSONLarge(rng) }},
	{"text_huge", 3, func(rng *rand.Rand, _ int) []byte { return genRawText(rng, 100_000+rng.Intn(50_000)) }},
	{"json_huge", 3, func(rng *rand.Rand, _ int) []byte { return genJSONHuge(rng) }},
	{"html_huge", 3, func(rng *rand.Rand, _ int) []byte { return genHTMLHuge(rng) }},
	// html_giant: 8 samples per hash, ~1 MB each — for tight KL estimation in
	// Phase 2b (data-pixel-dominated) and to widen the NIST STS stream beyond
	// the minimum 20 Mbits so the uniformity-of-p-values test can be run at
	// up to 100 sequences. Excluded from Phase 2c (startPixel enumeration is
	// O(P²) on container pixels).
	{"html_giant", 8, func(rng *rand.Rand, _ int) []byte { return genHTMLGiant(rng) }},
}

// ----------------------------------------------------------------------------
// Sample metadata dump
// ----------------------------------------------------------------------------

type sampleMeta struct {
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	Hash         string     `json:"hash"`         // dirname
	HashDisplay  string     `json:"hash_display"` // BENCH.md name
	HashWidth    int        `json:"hash_width"`
	Mode         string     `json:"mode"`         // "single" or "triple"
	PlaintextLen int        `json:"plaintext_len"`
	NonceHex     string     `json:"nonce_hex"`
	Width        int        `json:"width"`
	Height       int        `json:"height"`
	TotalPixels  int        `json:"total_pixels"`
	StartPixels  []int      `json:"start_pixels"` // len 1 (single) or 3 (triple, local to each third)
	NoiseSeed    []uint64   `json:"noise_seed"`
	DataSeeds    [][]uint64 `json:"data_seeds"`  // len 1 (single) or 3 (triple)
	StartSeeds   [][]uint64 `json:"start_seeds"` // len 1 (single) or 3 (triple)
}

// redteamMode reads ITB_REDTEAM_MODE env var (valid values: "single", "triple");
// defaults to "single" when unset.
func redteamMode(t *testing.T) string {
	s := os.Getenv("ITB_REDTEAM_MODE")
	if s == "" || s == "single" {
		return "single"
	}
	if s == "triple" {
		return "triple"
	}
	t.Fatalf("ITB_REDTEAM_MODE=%q: must be 'single' or 'triple'", s)
	return ""
}

// ----------------------------------------------------------------------------
// Main corpus generator
// ----------------------------------------------------------------------------

// redteamBarrierFill reads ITB_BARRIER_FILL env var (valid values: 1, 2, 4,
// 8, 16, 32); defaults to 1 (the shipped ITB default) when unset or invalid.
func redteamBarrierFill(t *testing.T) int {
	s := os.Getenv("ITB_BARRIER_FILL")
	if s == "" {
		return 1
	}
	for _, v := range []int{1, 2, 4, 8, 16, 32} {
		if fmt.Sprintf("%d", v) == s {
			return v
		}
	}
	t.Fatalf("ITB_BARRIER_FILL=%q: must be one of 1, 2, 4, 8, 16, 32", s)
	return 0
}

// TestRedTeamGenerate produces the attack corpus under tmp/.
// Settings:
//   - 1024-bit keys (Single Ouroboros)
//   - SetMaxWorkers(8) for parallel pixel processing during encryption
//   - SetBarrierFill(N) — taken from ITB_BARRIER_FILL env var (default 1)
//   - 128-bit nonce default
//
// Gated by ITB_REDTEAM=1 env var.
func TestRedTeamGenerate(t *testing.T) {
	if os.Getenv("ITB_REDTEAM") == "" {
		t.Skip("set ITB_REDTEAM=1 to generate red-team corpus (writes to tmp/)")
	}

	const keyBits = 1024
	barrierFill := redteamBarrierFill(t)
	mode := redteamMode(t)
	triple := mode == "triple"

	// Global ITB settings for the red-team corpus
	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	defer SetMaxWorkers(0) // restore default after test
	defer SetBarrierFill(1)

	hashes := buildHashSpecs(keyBits, triple)
	rng := rand.New(rand.NewSource(42)) // deterministic corpus

	tmpRoot, err := filepath.Abs("tmp")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	for _, hs := range hashes {
		if err := os.MkdirAll(filepath.Join(tmpRoot, "encrypted", hs.dirname), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(tmpRoot, "seeds", hs.dirname), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmpRoot, "plain"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	totalSamples := 0
	totalVerified := 0

	for _, k := range kinds {
		for i := 0; i < k.count; i++ {
			plaintext := k.gen(rng, i)
			plainName := fmt.Sprintf("%s_%03d.txt", k.name, i)
			plainPath := filepath.Join(tmpRoot, "plain", plainName)
			if err := os.WriteFile(plainPath, plaintext, 0o644); err != nil {
				t.Fatalf("write plain: %v", err)
			}

			for _, hs := range hashes {
				result, err := hs.encrypt(plaintext)
				if err != nil {
					t.Fatalf("encrypt %s/%s: %v", hs.dirname, plainName, err)
				}
				totalVerified++

				encBase := fmt.Sprintf("%s_%03d", k.name, i)
				encPath := filepath.Join(tmpRoot, "encrypted", hs.dirname, encBase+".bin")
				if err := os.WriteFile(encPath, result.Ciphertext, 0o644); err != nil {
					t.Fatalf("write enc: %v", err)
				}

				pixPath := filepath.Join(tmpRoot, "encrypted", hs.dirname, encBase+".pixel")
				var pixBuf []byte
				pixBuf = append(pixBuf, []byte(fmt.Sprintf("mode=%s\ntotal_pixels=%d\nwidth=%d\nheight=%d\nnonce_hex=%s\nhash=%s\nhash_width=%d\n",
					mode, result.TotalPixels, result.Width, result.Height, hex.EncodeToString(result.Nonce),
					hs.dirname, hs.width))...)
				if triple {
					third := result.TotalPixels / 3
					pixBuf = append(pixBuf, []byte(fmt.Sprintf("third_pixels_0=%d\nthird_pixels_1=%d\nthird_pixels_2=%d\n",
						third, third, result.TotalPixels-2*third))...)
					for i, sp := range result.StartPixels {
						pixBuf = append(pixBuf, []byte(fmt.Sprintf("start_pixel_%d=%d\n", i, sp))...)
					}
				} else {
					pixBuf = append(pixBuf, []byte(fmt.Sprintf("start_pixel=%d\n", result.StartPixels[0]))...)
				}
				if err := os.WriteFile(pixPath, pixBuf, 0o644); err != nil {
					t.Fatalf("write pixel: %v", err)
				}

				meta := sampleMeta{
					Name: encBase, Kind: k.name, Hash: hs.dirname, HashDisplay: hs.displayName, HashWidth: hs.width,
					Mode:         mode,
					PlaintextLen: len(plaintext), NonceHex: hex.EncodeToString(result.Nonce),
					Width: result.Width, Height: result.Height, TotalPixels: result.TotalPixels,
					StartPixels: result.StartPixels,
					NoiseSeed:   result.NoiseSeed,
					DataSeeds:   result.DataSeeds,
					StartSeeds:  result.StartSeeds,
				}
				metaPath := filepath.Join(tmpRoot, "seeds", hs.dirname, encBase+".json")
				metaBytes, _ := json.MarshalIndent(meta, "", "  ")
				if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
					t.Fatalf("write meta: %v", err)
				}
				totalSamples++
			}
		}
	}

	t.Logf("Generated %d samples (%d verified round-trip) across %d hash variants × %d kinds",
		totalSamples, totalVerified, len(hashes), len(kinds))
	t.Logf("  Settings: mode=%s, keyBits=%d, SetMaxWorkers(8), SetBarrierFill(%d), Nonce 128-bit",
		mode, keyBits, barrierFill)
	t.Logf("  Corpus root: %s", tmpRoot)
}

// ----------------------------------------------------------------------------
// Mega-stream generator for dieharder / NIST STS (large continuous ciphertext per hash)
// ----------------------------------------------------------------------------

// TestRedTeamGenerateMegaStreams produces large ciphertext streams (~240 MB per hash)
// under tmp/streams/<hash>_mega.bin for external randomness test suites.
// Gated by ITB_REDTEAM_MEGA=1.
func TestRedTeamGenerateMegaStreams(t *testing.T) {
	if os.Getenv("ITB_REDTEAM_MEGA") == "" {
		t.Skip("set ITB_REDTEAM_MEGA=1 to generate mega streams")
	}

	const keyBits = 1024
	const plaintextSize = 60 * 1024 * 1024 // 60 MB per encrypt (below ITB's 64 MB max)
	const samplesPerHash = 4                // 4 × 60 MB = ~240 MB ciphertext per hash
	barrierFill := redteamBarrierFill(t)

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	defer SetMaxWorkers(0)
	defer SetBarrierFill(1)

	hashes := buildHashSpecs(keyBits, false) // mega streams: single-mode only
	rng := rand.New(rand.NewSource(314159))
	streamsDir, _ := filepath.Abs("tmp/streams")
	os.MkdirAll(streamsDir, 0o755)

	for _, hs := range hashes {
		outPath := filepath.Join(streamsDir, fmt.Sprintf("%s_mega.bin", hs.dirname))
		out, err := os.Create(outPath)
		if err != nil {
			t.Fatalf("create %s: %v", outPath, err)
		}
		for i := 0; i < samplesPerHash; i++ {
			plain := make([]byte, plaintextSize)
			if _, err := rng.Read(plain); err != nil {
				t.Fatal(err)
			}
			result, err := hs.encrypt(plain)
			if err != nil {
				t.Fatalf("encrypt %s sample %d: %v", hs.dirname, i, err)
			}
			if _, err := out.Write(result.Ciphertext[headerSize():]); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		out.Close()
		info, _ := os.Stat(outPath)
		t.Logf("Wrote %s (%d bytes = %d MB)", outPath, info.Size(), info.Size()>>20)
	}
}

// ----------------------------------------------------------------------------
// Massive single-sample generator (one-off KL-floor probe)
// ----------------------------------------------------------------------------

// TestRedTeamGenerateSingleMassive produces ONE 63 MB plaintext encryption with
// one chosen hash (Single Ouroboros). Output under tmp/massive/<hash>.{bin,
// pixel,plain}. The companion analyzer is scripts/redteam/phase2_theory/
// kl_massive_single.py, which runs a chunked Phase 2b on the single sample to
// measure how close per-pixel KL gets to its theoretical floor at N = 77 M
// observations per candidate.
//
// Gated by ITB_REDTEAM_MASSIVE=<hash_name>. Valid names match the 10 dirnames:
//   fnv1a, md5, aescmac, siphash24, chacha20, areion256,
//   blake2s, blake3, blake2b, areion512
//
// Respects ITB_BARRIER_FILL (default 1). Plaintext is deterministic (rng
// seed 424242) so repeat runs produce identical input; the cryptographic
// seeds are fresh per run.
func TestRedTeamGenerateSingleMassive(t *testing.T) {
	hashName := os.Getenv("ITB_REDTEAM_MASSIVE")
	if hashName == "" {
		t.Skip("set ITB_REDTEAM_MASSIVE=<hash_name> to generate one 63 MB sample")
	}

	const keyBits = 1024
	const plaintextSize = 63 * 1024 * 1024 // just below ITB's 64 MB maxDataSize

	barrierFill := redteamBarrierFill(t)
	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	defer SetMaxWorkers(0)
	defer SetBarrierFill(1)

	hashes := buildHashSpecs(keyBits, false) // Single mode only
	var hs *hashSpec
	for i := range hashes {
		if hashes[i].dirname == hashName {
			hs = &hashes[i]
			break
		}
	}
	if hs == nil {
		names := []string{}
		for _, h := range hashes {
			names = append(names, h.dirname)
		}
		t.Fatalf("unknown hash %q; valid: %v", hashName, names)
	}

	rng := rand.New(rand.NewSource(424242))
	plain := make([]byte, plaintextSize)
	if _, err := rng.Read(plain); err != nil {
		t.Fatalf("rng: %v", err)
	}

	t.Logf("Encrypting %d bytes (%d MB) with %s (BarrierFill=%d)...",
		plaintextSize, plaintextSize>>20, hs.displayName, barrierFill)
	t0 := time.Now()
	result, err := hs.encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	t.Logf("  encrypt done in %s", time.Since(t0))

	outDir, _ := filepath.Abs("tmp/massive")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	binPath := filepath.Join(outDir, hs.dirname+".bin")
	pixPath := filepath.Join(outDir, hs.dirname+".pixel")
	plainPath := filepath.Join(outDir, hs.dirname+".plain")

	if err := os.WriteFile(binPath, result.Ciphertext, 0o644); err != nil {
		t.Fatalf("write bin: %v", err)
	}
	if err := os.WriteFile(plainPath, plain, 0o644); err != nil {
		t.Fatalf("write plain: %v", err)
	}
	pixContent := fmt.Sprintf("mode=single\nstart_pixel=%d\ntotal_pixels=%d\nwidth=%d\nheight=%d\nnonce_hex=%s\nhash=%s\nhash_width=%d\nbarrier_fill=%d\n",
		result.StartPixels[0], result.TotalPixels, result.Width, result.Height,
		hex.EncodeToString(result.Nonce), hs.dirname, hs.width, barrierFill)
	if err := os.WriteFile(pixPath, []byte(pixContent), 0o644); err != nil {
		t.Fatalf("write pixel: %v", err)
	}

	t.Logf("  plaintext -> %s (%d bytes)", plainPath, len(plain))
	t.Logf("  ciphertext -> %s (%d bytes = %d MB)", binPath, len(result.Ciphertext), len(result.Ciphertext)>>20)
	t.Logf("  metadata  -> %s", pixPath)
	t.Logf("Next: python3 scripts/redteam/phase2_theory/kl_massive_single.py %s", hs.dirname)
}
