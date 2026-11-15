package branding

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

func solid(w, h int, c color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	return img
}

func encode(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// chunk builds one PNG chunk with a correct CRC.
func chunk(typ string, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(data))) //nolint:gosec // test data is small
	out = append(out, typ...)
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(append([]byte(typ), data...)))
}

// withChunkAfterIHDR inserts a chunk straight after the header chunk of a PNG.
func withChunkAfterIHDR(png []byte, typ string, data []byte) []byte {
	const afterIHDR = 8 + 12 + 13
	out := append([]byte(nil), png[:afterIHDR]...)
	out = append(out, chunk(typ, data)...)
	return append(out, png[afterIHDR:]...)
}

// claimedSize builds a PNG whose header says w x h and whose pixel data is a few bytes: the
// decompression bomb shape.
func claimedSize(w, h uint32) []byte {
	ihdr := binary.BigEndian.AppendUint32(nil, w)
	ihdr = binary.BigEndian.AppendUint32(ihdr, h)
	ihdr = append(ihdr, 8, 6, 0, 0, 0)
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(make([]byte, 64))
	_ = zw.Close()
	out := append([]byte(nil), pngSignature...)
	out = append(out, chunk("IHDR", ihdr)...)
	out = append(out, chunk("IDAT", z.Bytes())...)
	return append(out, chunk("IEND", nil)...)
}

func TestNormalizeAcceptsAGoodLogoAndWritesItAgain(t *testing.T) {
	in := encode(t, solid(200, 100, color.NRGBA{R: 10, G: 200, B: 30, A: 255}))
	got, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.Width != 200 || got.Height != 100 {
		t.Errorf("size = %dx%d", got.Width, got.Height)
	}
	// Go wrote it: 8-bit RGB, or RGBA when some pixel is not opaque (Go's encoder picks), whatever the upload used.
	if depth, typ := ihdrFormat(got.PNG); depth != 8 || (typ != 2 && typ != 6) {
		t.Errorf("stored file has bit depth %d and colour type %d, want 8 and 2 or 6", depth, typ)
	}
	again, err := Normalize(in)
	if err != nil || again.SHA256 != got.SHA256 {
		t.Error("the same upload gives a different stored file")
	}
}

func TestNormalizeRefusesHostileInput(t *testing.T) {
	var jpg bytes.Buffer
	if err := jpeg.Encode(&jpg, solid(64, 64, color.NRGBA{A: 255}), nil); err != nil {
		t.Fatal(err)
	}
	good := encode(t, solid(64, 64, color.NRGBA{R: 255, A: 255}))
	apng := withChunkAfterIHDR(good, "acTL", []byte{0, 0, 0, 2, 0, 0, 0, 0})

	for name, tc := range map[string]struct {
		data []byte
		code errs.Code
	}{
		"text with a png name":               {[]byte("this is not an image, whatever its name says"), errs.InvalidRequest},
		"empty":                              {nil, errs.InvalidRequest},
		"a JPEG":                             {jpg.Bytes(), errs.InvalidRequest},
		"signature only":                     {pngSignature, errs.InvalidRequest},
		"truncated in the pixel data":        {good[:len(good)/2], errs.InvalidRequest},
		"truncated in the header":            {good[:20], errs.InvalidRequest},
		"flipped byte in the pixel data":     {flip(good, len(good)-20), errs.InvalidRequest},
		"animated PNG":                       {apng, errs.InvalidRequest},
		"bomb: 60000 x 60000 in a few bytes": {claimedSize(60000, 60000), errs.InvalidRequest},
		"bomb: 4 billion wide":               {claimedSize(1<<32-1, 16), errs.InvalidRequest},
		"1025 pixels wide":                   {encode(t, solid(1025, 16, color.NRGBA{A: 255})), errs.InvalidRequest},
		"1025 pixels tall":                   {encode(t, solid(16, 1025, color.NRGBA{A: 255})), errs.InvalidRequest},
		"absurdly small":                     {encode(t, solid(8, 8, color.NRGBA{A: 255})), errs.InvalidRequest},
		"1 pixel":                            {encode(t, solid(1, 1, color.NRGBA{A: 255})), errs.InvalidRequest},
		"fully transparent":                  {encode(t, solid(64, 64, color.NRGBA{R: 9})), errs.InvalidRequest},
		"valid size, data missing":           {claimedSize(1024, 1024), errs.InvalidRequest},
		"over 256 KB":                        {append(bytes.Clone(good), make([]byte, MaxBytes)...), errs.PayloadTooLarge},
		"over 256 KB and not a PNG":          {bytes.Repeat([]byte("x"), MaxBytes+1), errs.PayloadTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Normalize(tc.data)
			var e *errs.Error
			if !errors.As(err, &e) || e.Code != tc.code {
				t.Fatalf("error = %v, want %s", err, tc.code)
			}
		})
	}
}

// ihdrFormat reads the bit depth and colour type from the header chunk.
func ihdrFormat(b []byte) (depth, colourType byte) { return b[24], b[25] }

func flip(b []byte, at int) []byte {
	c := bytes.Clone(b)
	c[at] ^= 0xff
	return c
}

func TestNormalizeAcceptsExactlyTheLimits(t *testing.T) {
	for _, d := range [][2]int{{MinSide, MinSide}, {MaxSide, MaxSide}, {MaxSide, MinSide}, {MinSide, MaxSide}} {
		// A flat image compresses to almost nothing, so only the pixel limits are in play.
		if _, err := Normalize(encode(t, solid(d[0], d[1], color.NRGBA{B: 200, A: 255}))); err != nil {
			t.Errorf("%dx%d: %v", d[0], d[1], err)
		}
	}
}

func TestNormalizeStripsAncillaryChunks(t *testing.T) {
	in := encode(t, solid(64, 64, color.NRGBA{R: 255, A: 255}))
	in = withChunkAfterIHDR(in, "tEXt", []byte("Comment\x00test-fixture-secret-comment"))
	in = withChunkAfterIHDR(in, "iTXt", []byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00test-fixture-xmp"))
	in = withChunkAfterIHDR(in, "eXIf", []byte("test-fixture-gps-latitude"))
	in = withChunkAfterIHDR(in, "gAMA", []byte{0, 0, 0, 1})
	in = withChunkAfterIHDR(in, "zTXt", []byte("k\x00\x00x"))
	in = withChunkAfterIHDR(in, "pHYs", []byte{0, 0, 0, 1, 0, 0, 0, 1, 1})
	if !bytes.Contains(in, []byte("test-fixture-secret-comment")) {
		t.Fatal("the fixture lost its text chunk")
	}
	got, err := Normalize(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"tEXt", "iTXt", "zTXt", "eXIf", "gAMA", "pHYs", "iCCP", "tIME", "sRGB"} {
		if bytes.Contains(got.PNG, []byte(typ)) {
			t.Errorf("chunk %s survived the re-encode", typ)
		}
	}
	if bytes.Contains(got.PNG, []byte("test-fixture")) {
		t.Error("text from the upload survived")
	}
	// Only critical chunks remain.
	rest := got.PNG[len(pngSignature):]
	for len(rest) > 0 {
		n := binary.BigEndian.Uint32(rest[:4])
		if typ := string(rest[4:8]); !strings.Contains("IHDR IDAT IEND", typ) {
			t.Errorf("unexpected chunk %q", typ)
		}
		rest = rest[12+n:]
	}
}

func TestNormalizeFlattensOtherColourTypes(t *testing.T) {
	pal := image.NewPaletted(image.Rect(0, 0, 32, 32), color.Palette{color.NRGBA{A: 0}, color.NRGBA{R: 255, A: 255}})
	for i := range pal.Pix {
		pal.Pix[i] = uint8(i % 2) //nolint:gosec // 0 or 1
	}
	rgba64 := image.NewRGBA64(image.Rect(0, 0, 32, 32))
	for y := range 32 {
		for x := range 32 {
			rgba64.SetRGBA64(x, y, color.RGBA64{R: 0xffff, G: 0x8000, A: 0xffff})
		}
	}
	gray := image.NewGray16(image.Rect(0, 0, 32, 32))
	for i := range gray.Pix {
		gray.Pix[i] = 0xff
	}
	for name, img := range map[string]image.Image{"palette": pal, "16-bit RGBA": rgba64, "16-bit gray": gray} {
		got, err := Normalize(encode(t, img))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if depth, typ := ihdrFormat(got.PNG); depth != 8 || (typ != 2 && typ != 6) {
			t.Errorf("%s: stored with bit depth %d and colour type %d", name, depth, typ)
		}
	}
}

func TestRawGivesStraightAlphaPixelsInRowOrder(t *testing.T) {
	img := solid(16, 16, color.NRGBA{R: 1, G: 2, B: 3, A: 4})
	img.SetNRGBA(15, 0, color.NRGBA{R: 200, G: 100, B: 50, A: 255})
	img.SetNRGBA(0, 15, color.NRGBA{R: 7, G: 8, B: 9, A: 128})
	norm, err := Normalize(encode(t, img))
	if err != nil {
		t.Fatal(err)
	}
	pix, w, h, err := Raw(norm.PNG)
	if err != nil || w != 16 || h != 16 || len(pix) != 16*16*4 {
		t.Fatalf("Raw = %d bytes, %dx%d, %v", len(pix), w, h, err)
	}
	at := func(x, y int) []byte { return pix[(y*16+x)*4 : (y*16+x)*4+4] }
	if !bytes.Equal(at(0, 0), []byte{1, 2, 3, 4}) || !bytes.Equal(at(15, 0), []byte{200, 100, 50, 255}) || !bytes.Equal(at(0, 15), []byte{7, 8, 9, 128}) {
		t.Errorf("pixels = %v %v %v", at(0, 0), at(15, 0), at(0, 15))
	}
}

func TestRawRefusesWhatNormalizeWouldNot(t *testing.T) {
	for name, b := range map[string][]byte{
		"not a PNG": []byte("hello"),
		"a bomb":    claimedSize(60000, 60000),
		"too big":   bytes.Repeat([]byte("x"), MaxBytes+1),
	} {
		if _, _, _, err := Raw(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
