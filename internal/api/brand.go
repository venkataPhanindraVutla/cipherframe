package api

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"strconv"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/branding"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// logoFormOverhead is what the multipart framing and the three small fields may add to a logo file.
const logoFormOverhead = 16 << 10

// maxLogoRequestBytes is the body cap of the logo upload route.
const maxLogoRequestBytes = branding.MaxBytes + logoFormOverhead

// maxLogoFormParts bounds the members of the upload form: file, corner, opacity and enabled.
const maxLogoFormParts = 6

func (s *server) brandingService() (*branding.Service, error) {
	if s.branding == nil {
		return nil, errs.New(errs.DependencyUnavailable, "The brand logo is not available.")
	}
	return s.branding, nil
}

func brandLogoOut(l db.TenantLogo) gen.BrandLogo {
	return gen.BrandLogo{
		Version: l.ID.String(), Sha256: hex.EncodeToString(l.SHA256), SizeBytes: l.SizeBytes, Width: l.Width, Height: l.Height,
		Corner: gen.BrandLogoCorner(l.Corner), OpacityPercent: l.OpacityPercent, Enabled: l.Enabled,
		CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt,
	}
}

// GetBrandLogo returns the caller's tenant's current logo.
func (s *server) GetBrandLogo(ctx context.Context, _ gen.GetBrandLogoRequestObject) (gen.GetBrandLogoResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.brandingService()
	if err != nil {
		return nil, err
	}
	l, err := svc.Get(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return gen.GetBrandLogo200JSONResponse{Body: brandLogoOut(l), Headers: gen.GetBrandLogo200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// PutBrandLogo stores a new logo version from an uploaded PNG.
func (s *server) PutBrandLogo(ctx context.Context, req gen.PutBrandLogoRequestObject) (gen.PutBrandLogoResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.brandingService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	data, place, err := readLogoForm(req.Body)
	if err != nil {
		return nil, err
	}
	l, err := svc.Put(ctx, p.TenantID, actor, data, place)
	if err != nil {
		return nil, err
	}
	return gen.PutBrandLogo200JSONResponse{Body: brandLogoOut(l), Headers: gen.PutBrandLogo200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// readLogoForm reads the upload form: only the four known members, each once. The name the client
// gave the file is never read.
func readLogoForm(mr *multipart.Reader) ([]byte, branding.Placement, error) {
	var data []byte
	var place branding.Placement
	seen := map[string]bool{}
	bad := func(field, msg string) error {
		return errs.Invalid("The request is invalid.", []errs.FieldError{{Field: field, Message: msg}})
	}
	for i := 0; ; i++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, place, formError(err)
		}
		name := part.FormName()
		if i >= maxLogoFormParts || seen[name] {
			return nil, place, bad(name, "is sent more than once or the form has too many members")
		}
		seen[name] = true
		if name == "file" {
			if data, err = io.ReadAll(io.LimitReader(part, branding.MaxBytes+1)); err != nil {
				return nil, place, formError(err)
			}
			if len(data) > branding.MaxBytes {
				return nil, place, errs.New(errs.PayloadTooLarge, "The logo is larger than 256 KB.")
			}
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(part, maxFormField+1))
		if err != nil {
			return nil, place, formError(err)
		}
		if len(raw) > maxFormField {
			return nil, place, bad(name, "is too long")
		}
		switch name {
		case "corner":
			c := string(raw)
			place.Corner = &c
		case "opacity":
			n, err := strconv.Atoi(string(raw))
			if err != nil {
				return nil, place, bad("opacity", "must be a whole number from 10 to 100")
			}
			place.Opacity = &n
		case "enabled":
			var v bool
			switch string(raw) {
			case "true":
				v = true
			case "false":
			default:
				return nil, place, bad("enabled", "must be true or false")
			}
			place.Enabled = &v
		default:
			return nil, place, bad("form", "has a member that is not part of the request")
		}
	}
	if !seen["file"] {
		return nil, place, bad("file", "is required")
	}
	return data, place, nil
}

// UpdateBrandLogo changes the placement of the current logo.
func (s *server) UpdateBrandLogo(ctx context.Context, req gen.UpdateBrandLogoRequestObject) (gen.UpdateBrandLogoResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.brandingService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	place := branding.Placement{Opacity: req.Body.OpacityPercent, Enabled: req.Body.Enabled}
	if req.Body.Corner != nil {
		c := string(*req.Body.Corner)
		place.Corner = &c
	}
	l, err := svc.Update(ctx, p.TenantID, actor, place)
	if err != nil {
		return nil, err
	}
	return gen.UpdateBrandLogo200JSONResponse{Body: brandLogoOut(l), Headers: gen.UpdateBrandLogo200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// DeleteBrandLogo removes the tenant's logo.
func (s *server) DeleteBrandLogo(ctx context.Context, _ gen.DeleteBrandLogoRequestObject) (gen.DeleteBrandLogoResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.brandingService()
	if err != nil {
		return nil, err
	}
	if err := svc.Delete(ctx, p.TenantID, actor); err != nil {
		return nil, err
	}
	return gen.DeleteBrandLogo204Response{Headers: gen.DeleteBrandLogo204ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
