package hls_test

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // test data in the package directory
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file (run go test ./internal/hls -update to refresh):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ivOf(t *testing.T, s string) hls.IV {
	t.Helper()
	var iv hls.IV
	copy(iv[:], mustHex(t, s))
	return iv
}

// ---- cipher -----------------------------------------------------------------------------------

// NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt.
const (
	nistKey = "2b7e151628aed2a6abf7158809cf4f3c"
	nistIV  = "000102030405060708090a0b0c0d0e0f"
	nistP1  = "6bc1bee22e409f96e93d7e117393172a"
	nistP2  = "ae2d8a571e03ac9c9eb76fac45af8e51"
	nistC1  = "7649abac8119b246cee98e9b12e9197d"
	nistC2  = "5086cb9b507219ee95db113a917678b2"
)

func xor16(a, b []byte) []byte {
	out := make([]byte, 16)
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// ecb encrypts one block with the raw AES primitive, independent of the CBC mode implementation
// under test.
func ecb(t *testing.T, key, block []byte) []byte {
	t.Helper()
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	c.Encrypt(out, block)
	return out
}

func TestEncryptSegmentMatchesTheNISTVector(t *testing.T) {
	key, iv := mustHex(t, nistKey), ivOf(t, nistIV)
	plain := append(mustHex(t, nistP1), mustHex(t, nistP2)...)
	ct, err := hls.EncryptSegment(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	// Two aligned blocks gain one full block of PKCS#7 padding (sixteen bytes of 0x10).
	if len(ct) != 48 {
		t.Fatalf("ciphertext length = %d, want 48", len(ct))
	}
	if got := hex.EncodeToString(ct[:32]); got != nistC1+nistC2 {
		t.Fatalf("first two blocks = %s, want the NIST vector %s", got, nistC1+nistC2)
	}
	pad := bytes.Repeat([]byte{0x10}, 16)
	want3 := ecb(t, key, xor16(mustHex(t, nistC2), pad))
	if !bytes.Equal(ct[32:], want3) {
		t.Fatalf("padding block = %x, want %x", ct[32:], want3)
	}
}

func TestEncryptSegmentPadsAnUnalignedInput(t *testing.T) {
	key, iv := mustHex(t, nistKey), ivOf(t, nistIV)
	tail := []byte{1, 2, 3, 4, 5}
	plain := append(mustHex(t, nistP1), tail...)
	ct, err := hls.EncryptSegment(key, iv, plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 32 || hex.EncodeToString(ct[:16]) != nistC1 {
		t.Fatalf("unexpected ciphertext %x", ct)
	}
	last := append(append([]byte(nil), tail...), bytes.Repeat([]byte{11}, 11)...) // 5 data + 11 x 0x0b
	if want := ecb(t, key, xor16(mustHex(t, nistC1), last)); !bytes.Equal(ct[16:], want) {
		t.Fatalf("second block = %x, want %x", ct[16:], want)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := mustHex(t, nistKey)
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 1000, 6*1024*1024 + 3} {
		iv, err := hls.NewIV()
		if err != nil {
			t.Fatal(err)
		}
		plain := bytes.Repeat([]byte{0xAB}, n)
		for i := range plain {
			plain[i] ^= byte(i * 7)
		}
		orig := append([]byte(nil), plain...)
		ct, err := hls.EncryptSegment(key, iv, plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, orig) {
			t.Fatalf("n=%d: EncryptSegment modified its input", n)
		}
		if len(ct)%16 != 0 || len(ct) <= n {
			t.Fatalf("n=%d: ciphertext length %d", n, len(ct))
		}
		got, err := hls.DecryptSegment(key, iv, ct)
		if err != nil || !bytes.Equal(got, orig) {
			t.Fatalf("n=%d: round trip failed: %v", n, err)
		}
	}
}

func TestDecryptRejectsBadInput(t *testing.T) {
	key, iv := mustHex(t, nistKey), ivOf(t, nistIV)
	ct, err := hls.EncryptSegment(key, iv, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	if p, err := hls.DecryptSegment(wrong, iv, ct); err == nil && bytes.Equal(p, []byte("hello")) {
		t.Fatal("decrypted with the wrong key")
	}
	if _, err := hls.DecryptSegment(key, iv, ct[:len(ct)-1]); err == nil {
		t.Fatal("accepted a ciphertext that is not block aligned")
	}
	if _, err := hls.DecryptSegment(key, iv, nil); err == nil {
		t.Fatal("accepted an empty ciphertext")
	}
	if _, err := hls.EncryptSegment(key[:15], iv, ct); err == nil {
		t.Fatal("accepted a 15 byte key")
	}
}

func TestIVsAreFreshAndSixteenBytes(t *testing.T) {
	seen := map[hls.IV]bool{}
	for range 64 {
		iv, err := hls.NewIV()
		if err != nil {
			t.Fatal(err)
		}
		if seen[iv] || iv == (hls.IV{}) {
			t.Fatal("repeated or zero IV")
		}
		seen[iv] = true
	}
}

// ---- playlists --------------------------------------------------------------------------------

func TestMediaPlaylistGolden(t *testing.T) {
	p := hls.MediaPlaylist{
		InitURI: "init.mp4",
		Segments: []hls.Segment{
			{URI: "seg-0.m4s", Duration: 6 * time.Second, IV: ivOf(t, "000102030405060708090a0b0c0d0e0f")},
			{URI: "seg-1.m4s", Duration: 6 * time.Second, IV: ivOf(t, "f0e1d2c3b4a5968778695a4b3c2d1e0f")},
			{URI: "seg-2.m4s", Duration: 2002 * time.Millisecond, IV: ivOf(t, "00000000000000000000000000000001")},
		},
	}
	got, err := hls.RenderMedia(p)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "media.m3u8.golden", got)
	for _, banned := range []string{"http://", "https://", "token", "session", "?"} {
		if strings.Contains(got, banned) {
			t.Errorf("stored playlist contains %q", banned)
		}
	}
	// The init segment is declared before any key, so no key applies to it (RFC 8216 4.3.2.4).
	if strings.Index(got, "#EXT-X-MAP") > strings.Index(got, "#EXT-X-KEY") {
		t.Error("EXT-X-MAP must precede the first EXT-X-KEY so the init segment stays unencrypted")
	}
	if n := strings.Count(got, "#EXT-X-KEY"); n != 3 {
		t.Errorf("EXT-X-KEY count = %d, want one per segment", n)
	}
}

func TestMediaPlaylistTargetDurationRoundsUp(t *testing.T) {
	got, err := hls.RenderMedia(hls.MediaPlaylist{InitURI: "init.mp4", Segments: []hls.Segment{
		{URI: "seg-0.m4s", Duration: 6006 * time.Millisecond},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "#EXT-X-TARGETDURATION:7\n") {
		t.Errorf("target duration must be the ceiling of the longest segment:\n%s", got)
	}
}

func TestMediaPlaylistRejectsBadInput(t *testing.T) {
	good := hls.Segment{URI: "seg-0.m4s", Duration: time.Second}
	for name, p := range map[string]hls.MediaPlaylist{
		"no segments":       {InitURI: "init.mp4"},
		"no init":           {Segments: []hls.Segment{good}},
		"zero duration":     {InitURI: "init.mp4", Segments: []hls.Segment{{URI: "a"}}},
		"newline in URI":    {InitURI: "init.mp4", Segments: []hls.Segment{{URI: "a\n#EXT-X-ENDLIST", Duration: time.Second}}},
		"quote in init URI": {InitURI: "in\"it.mp4", Segments: []hls.Segment{good}},
	} {
		if _, err := hls.RenderMedia(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestMasterPlaylistGolden(t *testing.T) {
	vs := []hls.Variant{
		{URI: "720p/playlist.m3u8", Bandwidth: 2_900_000, AverageBandwidth: 2_300_000, Width: 1280, Height: 720, Codecs: "avc1.64001f,mp4a.40.2", FrameRate: 30},
		{URI: "240p/playlist.m3u8", Bandwidth: 450_000, AverageBandwidth: 380_000, Width: 426, Height: 240, Codecs: "avc1.640015,mp4a.40.2", FrameRate: 30},
		{URI: "480p/playlist.m3u8", Bandwidth: 1_400_000, AverageBandwidth: 1_100_000, Width: 854, Height: 480, Codecs: "avc1.64001e,mp4a.40.2", FrameRate: 29.97},
	}
	got, err := hls.RenderMaster(vs)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "master.m3u8.golden", got)
	if vs[0].URI != "720p/playlist.m3u8" {
		t.Error("RenderMaster reordered the caller's slice")
	}
}

func TestMasterPlaylistRejectsIncompleteVariants(t *testing.T) {
	ok := hls.Variant{URI: "a/playlist.m3u8", Bandwidth: 1, AverageBandwidth: 1, Width: 2, Height: 2, Codecs: "avc1.640015", FrameRate: 30}
	if _, err := hls.RenderMaster([]hls.Variant{ok}); err != nil {
		t.Fatal(err)
	}
	if _, err := hls.RenderMaster(nil); err == nil {
		t.Error("accepted no variants")
	}
	for name, mod := range map[string]func(*hls.Variant){
		"no bandwidth": func(v *hls.Variant) { v.Bandwidth = 0 },
		"no codecs":    func(v *hls.Variant) { v.Codecs = "" },
		"no rate":      func(v *hls.Variant) { v.FrameRate = 0 },
		"quote":        func(v *hls.Variant) { v.Codecs = "a\"b" },
		"bad uri":      func(v *hls.Variant) { v.URI = "a b" },
	} {
		v := ok
		mod(&v)
		if _, err := hls.RenderMaster([]hls.Variant{v}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// ---- codec strings ----------------------------------------------------------------------------

func box(typ string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body))) //nolint:gosec // small test data
	out = append(out, typ...)
	return append(out, body...)
}

// descriptor builds an MPEG-4 descriptor with a one byte length.
func descriptor(tag byte, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	return append([]byte{tag, byte(len(body))}, body...)
}

func avcInit(profile, compat, level byte) []byte {
	avcC := box("avcC", []byte{1, profile, compat, level, 0xff, 0xe1})
	avc1 := box("avc1", make([]byte, 78), avcC)
	return box("moov", box("trak", box("mdia", box("minf", box("stbl", box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}, avc1)))))) //nolint:lll
}

func aacInit(objectType, aot byte) []byte {
	asc := descriptor(0x05, []byte{aot << 3, 0x10})
	dec := descriptor(0x04, []byte{objectType, 0x15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, asc)
	es := descriptor(0x03, []byte{0, 2, 0}, dec)
	esds := box("esds", []byte{0, 0, 0, 0}, es)
	mp4a := box("mp4a", make([]byte, 28), esds)
	return box("moov", box("trak", box("stsd", []byte{0, 0, 0, 0, 0, 0, 0, 1}, mp4a)))
}

func TestVideoCodecFromTheInitSegment(t *testing.T) {
	for _, tc := range []struct {
		profile, compat, level byte
		want                   string
	}{
		{0x64, 0x00, 0x28, "avc1.640028"},
		{0x64, 0x00, 0x1f, "avc1.64001f"},
		{0x4d, 0x40, 0x1e, "avc1.4d401e"},
	} {
		got, err := hls.VideoCodec(avcInit(tc.profile, tc.compat, tc.level))
		if err != nil || got != tc.want {
			t.Errorf("VideoCodec = %q, %v; want %q", got, err, tc.want)
		}
	}
	for name, in := range map[string][]byte{
		"empty": nil, "no avc1": box("moov", box("avcC", []byte{1, 2, 3, 4})), "bare avcC": box("avc1", make([]byte, 4)),
		"truncated": avcInit(0x64, 0, 0x28)[:len(avcInit(0x64, 0, 0x28))-5],
	} {
		if _, err := hls.VideoCodec(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAudioCodecFromTheInitSegment(t *testing.T) {
	if got, err := hls.AudioCodec(aacInit(0x40, 2)); err != nil || got != "mp4a.40.2" {
		t.Errorf("AudioCodec = %q, %v; want mp4a.40.2", got, err)
	}
	if got, err := hls.AudioCodec(aacInit(0x40, 5)); err != nil || got != "mp4a.40.5" {
		t.Errorf("AudioCodec (HE-AAC) = %q, %v", got, err)
	}
	if _, err := hls.AudioCodec(aacInit(0x6b, 2)); err == nil {
		t.Error("accepted an MP3 object type as AAC")
	}
	whole := aacInit(0x40, 2)
	for _, n := range []int{0, 10, len(whole) - 3} {
		if _, err := hls.AudioCodec(whole[:n]); err == nil {
			t.Errorf("accepted an init segment truncated to %d bytes", n)
		}
	}
}
