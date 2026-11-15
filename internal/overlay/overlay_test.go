package overlay

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

func TestValidateTemplate(t *testing.T) {
	ok := []string{
		"{session_code}",
		"{session_code} {date} {time} UTC",
		"Confidential - {date}",
		"{time}{time}{time}",
		"Ünïcödé {session_code} 日本語",
		"100% \"quoted\" $5 {date}", // plain text: the player draws it, never parses it
		strings.Repeat("a", MaxTemplateChars-len("{date}")) + "{date}",
	}
	for _, s := range ok {
		if err := ValidateTemplate(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	bad := map[string]string{
		"empty":                "",
		"no placeholder":       "Confidential",
		"unknown placeholder":  "{viewer_id} {date}",
		"viewer email":         "{email}",
		"case differs":         "{SESSION_CODE}",
		"spaces inside":        "{ date }",
		"nested":               "{{date}}",
		"stray open":           "{date} {",
		"stray close":          "} {date}",
		"partial":              "{session_code",
		"too long":             strings.Repeat("a", MaxTemplateChars-len("{date}")+1) + "{date}",
		"newline":              "{date}\n{time}",
		"carriage return":      "{date}\r",
		"tab":                  "{date}\t{time}",
		"nul":                  "{date}\x00",
		"escape":               "{date}\x1b[31m",
		"line separator":       "{date}\u2028{time}",
		"paragraph separator":  "{date}\u2029",
		"right-to-left":        "{date}\u202e",
		"zero width":           "{date}\u200b",
		"bom":                  "\ufeff{date}",
		"private use":          "{date}\ue000",
		"invalid utf8":         "{date}\xff",
		"replacement char":     "{date}\ufffd",
		"script tag":           "<script>alert(1)</script>{date}",
		"html entity":          "&lt;{date}",
		"angle bracket":        "{date} >",
		"svg":                  "<svg onload=x>{date}",
		"template literal":     "${date}{time}${7*7}",
		"placeholder smuggled": "{date{time}}",
	}
	for name, s := range bad {
		if err := ValidateTemplate(s); err == nil {
			t.Errorf("%s: %q was accepted", name, s)
		}
	}
	// 120 characters are counted as characters, not bytes.
	if err := ValidateTemplate(strings.Repeat("é", MaxTemplateChars-len("{date}")) + "{date}"); err != nil {
		t.Errorf("120 multi-byte characters refused: %v", err)
	}
}

func TestValidateSettings(t *testing.T) {
	good := db.DefaultOverlaySettings()
	if f := ValidateSettings(good); len(f) != 0 {
		t.Fatalf("defaults are invalid: %v", f)
	}
	cases := map[string]func(*db.OverlaySettings){
		"template":           func(s *db.OverlaySettings) { s.Template = "{nope}" },
		"opacity":            func(s *db.OverlaySettings) { s.Opacity = 0.04 },
		"font_size_fraction": func(s *db.OverlaySettings) { s.FontSizeFraction = 0.2 },
		"color":              func(s *db.OverlaySettings) { s.Color = "#ffffff" },
	}
	for field, mut := range cases {
		s := good
		mut(&s)
		f := ValidateSettings(s)
		if len(f) != 1 || f[0].Field != field {
			t.Errorf("%s: %v", field, f)
		}
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), -1, 0, 1} {
		s := good
		s.Opacity = v
		if len(ValidateSettings(s)) == 0 {
			t.Errorf("opacity %v accepted", v)
		}
	}
	for _, c := range []string{"", "red", "#FFF", "#GGGGGG", "#FFFFFFF", "FFFFFF0", "#FFFFFF\n"} {
		s := good
		s.Color = c
		if len(ValidateSettings(s)) == 0 {
			t.Errorf("color %q accepted", c)
		}
	}
}

func TestSessionCode(t *testing.T) {
	tenant := id.New[id.TenantKind]()
	h := make([]byte, 32)
	c := SessionCode(h, tenant)
	if !ValidCode(c) || len(c) != CodeLen {
		t.Fatalf("code %q", c)
	}
	if SessionCode(h, tenant) != c {
		t.Fatal("not deterministic")
	}
	if strings.ContainsAny(c, "01IO") {
		t.Fatalf("ambiguous character in %q", c)
	}
	// Another session or tenant gives another code; 1000 sessions do not collide.
	seen := map[string]bool{}
	for i := range 1000 {
		h[0], h[1] = byte(i), byte(i>>8)
		seen[SessionCode(h, tenant)] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("%d distinct codes of 1000", len(seen))
	}
	if SessionCode(h, id.New[id.TenantKind]()) == SessionCode(h, tenant) {
		t.Fatal("tenants share a code")
	}
	// The code is not a prefix or piece of the session hash or the session ID.
	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	code := SessionCode(db.SessionHash(sid), tenant)
	if strings.Contains(strings.ToUpper(sid.String()), code) {
		t.Fatal("the code appears in the session ID")
	}
	for _, bad := range []string{"", "ABCDEFG", "ABCDEFGHJ", "abcdefgh", "ABCDEFG0", "ABCDEFGI", "ABCDEFG1", "ABCDEFGO"} {
		if ValidCode(bad) {
			t.Errorf("%q is a valid code", bad)
		}
	}
}

func TestSeedIsOneWayAndStable(t *testing.T) {
	sid, err := id.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s := Seed(sid)
	if len(s) != 16 || s != Seed(sid) {
		t.Fatalf("seed %q", s)
	}
	if strings.Contains(sid.String(), s) {
		t.Fatal("the seed appears in the session identity")
	}
	if _, err := ParsePath(s); err != nil {
		t.Fatal(err)
	}
}

func TestParsePathRejects(t *testing.T) {
	for _, s := range []string{"", "00", "zz00000000000000", "00000000000000000", "000000000000000"} {
		if _, err := ParsePath(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func seedFor(i int) string {
	sid, err := id.NewSession()
	if err != nil {
		panic(err)
	}
	_ = i
	return Seed(sid)
}

func TestPathStaysInsideAndIsContinuous(t *testing.T) {
	for i := range 200 {
		p, err := ParsePath(seedFor(i))
		if err != nil {
			t.Fatal(err)
		}
		pu, pv := p.At(0)
		const step = 0.25
		maxStep := math.Pi * 3 / PeriodSeconds * step * 1.0001
		for ts := step; ts <= 2*PeriodSeconds; ts += step {
			u, v := p.At(ts)
			if u < 0 || u > 1 || v < 0 || v > 1 {
				t.Fatalf("seed %d: (%v, %v) at %v is outside the room", i, u, v, ts)
			}
			if math.Abs(u-pu) > maxStep || math.Abs(v-pv) > maxStep {
				t.Fatalf("seed %d: jump at %v", i, ts)
			}
			// A box of any size stays between the margins.
			for _, box := range []float64{0.05, 0.3, 0.9, 1.5} {
				x := Place(u, box)
				if x < Margin || x+math.Min(box, 1-2*Margin) > 1-Margin+1e-12 {
					t.Fatalf("box %v at u=%v placed at %v", box, u, x)
				}
			}
			pu, pv = u, v
		}
		// Closed: the path repeats after one period.
		u0, v0 := p.At(3.7)
		u1, v1 := p.At(3.7 + PeriodSeconds)
		if math.Abs(u0-u1) > 1e-9 || math.Abs(v0-v1) > 1e-9 {
			t.Fatalf("seed %d is not closed", i)
		}
	}
}

func TestDifferentSessionsGetDifferentPaths(t *testing.T) {
	seen := map[Path]bool{}
	seeds := map[string]bool{}
	for i := range 500 {
		s := seedFor(i)
		seeds[s] = true
		p, _ := ParsePath(s)
		seen[p] = true
	}
	if len(seeds) != 500 || len(seen) != 500 {
		t.Fatalf("%d seeds and %d paths of 500 sessions", len(seeds), len(seen))
	}
	// All six frequency pairs are used.
	pairs := map[[2]int]bool{}
	for p := range seen {
		pairs[[2]int{p.KX, p.KY}] = true
	}
	if len(pairs) != len(freqPairs) {
		t.Fatalf("%d frequency pairs in use", len(pairs))
	}
}

type vectorFile struct {
	Algorithm     string         `json:"algorithm"`
	PeriodSeconds int            `json:"period_seconds"`
	Margin        float64        `json:"margin"`
	Tolerance     float64        `json:"tolerance"`
	Vectors       []seedVector   `json:"vectors"`
	Placements    []placeVector  `json:"placements"`
	Notes         map[string]any `json:"notes,omitempty"`
}

type seedVector struct {
	Seed      string      `json:"seed"`
	KX        int         `json:"kx"`
	KY        int         `json:"ky"`
	PhaseX    float64     `json:"phase_x"`
	PhaseY    float64     `json:"phase_y"`
	Positions []positionV `json:"positions"`
}

type positionV struct {
	T float64 `json:"t"`
	U float64 `json:"u"`
	V float64 `json:"v"`
}

type placeVector struct {
	U      float64 `json:"u"`
	Box    float64 `json:"box"`
	Offset float64 `json:"offset"`
}

const vectorPath = "../../spec/test-vectors/overlay/drift.json"

var (
	vectorSeeds = []string{"0000000000000000", "ffffffffffffffff", "0123456789abcdef", "a1b2c3d4e5f60718", "5d41402abc4b2a76", "7f3e91c2000000ff"}
	vectorTimes = []float64{0, 1, 7.5, 60, 119.25, 120, 239.9, 240, 1000.125}
)

// TestVectors checks the reference implementation against the published vectors. Run it with
// OVERLAY_UPDATE_VECTORS=1 to rewrite the file after a deliberate change of the algorithm.
func TestVectors(t *testing.T) {
	if os.Getenv("OVERLAY_UPDATE_VECTORS") == "1" {
		f := vectorFile{Algorithm: Algorithm, PeriodSeconds: PeriodSeconds, Margin: Margin, Tolerance: 1e-9}
		for _, s := range vectorSeeds {
			p, err := ParsePath(s)
			if err != nil {
				t.Fatal(err)
			}
			v := seedVector{Seed: s, KX: p.KX, KY: p.KY, PhaseX: p.PhaseX, PhaseY: p.PhaseY}
			for _, ts := range vectorTimes {
				u, w := p.At(ts)
				v.Positions = append(v.Positions, positionV{ts, u, w})
			}
			f.Vectors = append(f.Vectors, v)
		}
		for _, u := range []float64{0, 0.25, 1} {
			for _, box := range []float64{0.1, 0.5, 0.96, 1.2} {
				f.Placements = append(f.Placements, placeVector{u, box, Place(u, box)})
			}
		}
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, append(b, '\n'), 0o644); err != nil { //nolint:gosec // a spec file
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Algorithm != Algorithm || f.PeriodSeconds != PeriodSeconds || f.Margin != Margin || len(f.Vectors) < 5 {
		t.Fatalf("vector header: %+v", f)
	}
	near := func(a, b float64) bool { return math.Abs(a-b) <= f.Tolerance }
	for _, v := range f.Vectors {
		p, err := ParsePath(v.Seed)
		if err != nil {
			t.Fatal(err)
		}
		if p.KX != v.KX || p.KY != v.KY || !near(p.PhaseX, v.PhaseX) || !near(p.PhaseY, v.PhaseY) {
			t.Errorf("seed %s: path %+v, vector %+v", v.Seed, p, v)
		}
		for _, pos := range v.Positions {
			if u, w := p.At(pos.T); !near(u, pos.U) || !near(w, pos.V) {
				t.Errorf("seed %s t=%v: (%v, %v), vector (%v, %v)", v.Seed, pos.T, u, w, pos.U, pos.V)
			}
		}
	}
	for _, pl := range f.Placements {
		if got := Place(pl.U, pl.Box); !near(got, pl.Offset) {
			t.Errorf("place(%v, %v) = %v, vector %v", pl.U, pl.Box, got, pl.Offset)
		}
	}
}

// TestGoldenDerivations freezes the seed and code derivations: a change here changes every
// session's path or code, so it is a decision, not a refactor.
func TestGoldenDerivations(t *testing.T) {
	sid, err := id.ParseSession("ses_" + strings.Repeat("1", 51) + "0")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := id.Parse[id.TenantKind]("ten_" + strings.Repeat("1", 25) + "0")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Seed(sid), "94027ae60bbd3256"; got != want {
		t.Errorf("seed = %s, want %s", got, want)
	}
	if got, want := SessionCode(db.SessionHash(sid), tenant), "UHKFV9HB"; got != want {
		t.Errorf("code = %s, want %s", got, want)
	}
}
