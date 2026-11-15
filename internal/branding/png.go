// Package branding is the per-tenant brand logo (M7-4, ADR 0049): the upload checks, the immutable
// stored versions, and the placement the transcode burns in.
//
// The logo is untrusted input that is decoded by software on the worker. Normalize therefore reads
// it with Go's own PNG decoder under hard bounds, and stores only what Go's encoder writes back, so
// no ancillary chunk, text or metadata survives. The worker never hands even that file to FFmpeg: it
// decodes it again with Go and gives FFmpeg raw pixels (see Raw).
package branding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"image"
	"image/draw"
	"image/png"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Limits of a logo (ADR 0043).
const (
	// MaxBytes is the largest upload, and the largest stored file.
	MaxBytes = 256 << 10
	// MaxSide is the longest side in pixels.
	MaxSide = 1024
	// MinSide is the shortest side in pixels. A smaller image is not a logo, and scaled up to a
	// share of the video width it would be a smear.
	MinSide = 16
)

// pngSignature opens every PNG file.
var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// Normalized is a logo as it is stored: the PNG that Go's encoder wrote, its hash and its size.
type Normalized struct {
	PNG           []byte
	SHA256        [sha256.Size]byte
	Width, Height int
}

func invalid(msg string) error {
	return errs.Invalid("The logo is invalid.", []errs.FieldError{{Field: "file", Message: msg}})
}

// Normalize checks an uploaded logo and re-encodes it.
//
// The order matters: the size cap first, then the PNG signature, then the chunk list (an animated
// PNG is refused), then the header's dimensions, and only then the full decode, so a few hundred
// bytes that claim a billion pixels are refused before anything is allocated for them. The decoded
// pixels are written back through Go's PNG encoder as 8-bit non-premultiplied RGBA (the encoder
// drops the alpha channel of an image that is fully opaque). The client's
// file name is never an input.
func Normalize(data []byte) (Normalized, error) {
	if len(data) > MaxBytes {
		return Normalized{}, errs.New(errs.PayloadTooLarge, "The logo is larger than 256 KB.")
	}
	if !bytes.HasPrefix(data, pngSignature) {
		return Normalized{}, invalid("is not a PNG file")
	}
	if err := refuseAnimated(data); err != nil {
		return Normalized{}, err
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return Normalized{}, invalid("is not a valid PNG file")
	}
	if cfg.Width > MaxSide || cfg.Height > MaxSide {
		return Normalized{}, invalid("is larger than 1024 pixels on its longer side")
	}
	if cfg.Width < MinSide || cfg.Height < MinSide {
		return Normalized{}, invalid("is smaller than 16 pixels on a side")
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return Normalized{}, invalid("is not a valid PNG file")
	}
	rgba := toNRGBA(img)
	if fullyTransparent(rgba) {
		return Normalized{}, invalid("is fully transparent")
	}
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, rgba); err != nil {
		return Normalized{}, errs.Wrap(errs.InternalError, "", err)
	}
	if buf.Len() > MaxBytes {
		return Normalized{}, errs.New(errs.PayloadTooLarge, "The logo is larger than 256 KB after it is re-encoded.")
	}
	b := rgba.Bounds()
	return Normalized{PNG: buf.Bytes(), SHA256: sha256.Sum256(buf.Bytes()), Width: b.Dx(), Height: b.Dy()}, nil
}

// Raw decodes a stored logo (a PNG that Normalize produced) to straight-alpha RGBA bytes, four per
// pixel in row order, for FFmpeg's rawvideo input. It applies the same size bounds, so a stored
// object that was swapped for something else is refused too.
func Raw(stored []byte) (pix []byte, width, height int, err error) {
	if len(stored) > MaxBytes || !bytes.HasPrefix(stored, pngSignature) {
		return nil, 0, 0, invalid("is not a stored logo")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(stored))
	if err != nil || cfg.Width > MaxSide || cfg.Height > MaxSide || cfg.Width < MinSide || cfg.Height < MinSide {
		return nil, 0, 0, invalid("is not a stored logo")
	}
	img, err := png.Decode(bytes.NewReader(stored))
	if err != nil {
		return nil, 0, 0, invalid("is not a stored logo")
	}
	n := toNRGBA(img)
	return n.Pix, cfg.Width, cfg.Height, nil // toNRGBA allocates a zero-origin image: Stride is 4*Width
}

// toNRGBA converts any decoded PNG (palette, gray, 16-bit, with or without alpha) to 8-bit
// non-premultiplied RGBA with a zero origin.
func toNRGBA(img image.Image) *image.NRGBA {
	b := img.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(out, out.Bounds(), img, b.Min, draw.Src)
	return out
}

func fullyTransparent(img *image.NRGBA) bool {
	for i := 3; i < len(img.Pix); i += 4 {
		if img.Pix[i] != 0 {
			return false
		}
	}
	return true
}

// refuseAnimated walks the chunk list and refuses an animated PNG (APNG): it carries an acTL chunk.
// Go's decoder would show only the default image and silently drop the animation, which is not what
// a tenant who sent an animation expects, so the file is refused instead of flattened. A chunk that
// runs past the end of the data stops the walk; the decoder then reports the damage.
func refuseAnimated(data []byte) error {
	rest := data[len(pngSignature):]
	for len(rest) >= 8 {
		n := binary.BigEndian.Uint32(rest[:4])
		typ := string(rest[4:8])
		if typ == "acTL" || typ == "fcTL" || typ == "fdAT" {
			return invalid("is an animated PNG; send a still image")
		}
		if typ == "IEND" || uint64(n)+12 > uint64(len(rest)) {
			return nil
		}
		rest = rest[12+n:]
	}
	return nil
}
