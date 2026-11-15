package api

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/subtitles"
)

// maxFormField bounds a text member of the upload form (language, label, default).
const maxFormField = 1024

// maxFormParts bounds how many members the upload form may have: there are four.
const maxFormParts = 8

func (s *server) subtitleService() (*subtitles.Service, error) {
	if s.subtitles == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Subtitles are not available.")
	}
	return s.subtitles, nil
}

func parseSubtitleID(s string) (id.SubtitleID, error) {
	t, err := id.Parse[id.SubtitleKind](s)
	if err != nil {
		return id.SubtitleID{}, errs.New(errs.NotFound, "No such subtitle track.")
	}
	return t, nil
}

func subtitleOut(t db.Subtitle) gen.SubtitleTrack {
	return gen.SubtitleTrack{
		Id: t.ID.String(), AssetId: t.AssetID.String(), Language: t.Language, Label: t.Label, Default: t.Default,
		Origin: gen.SubtitleTrackOrigin(t.Origin), CueCount: t.CueCount, SizeBytes: t.SizeBytes,
		Sha256: hex.EncodeToString(t.SHA256), CreatedAt: t.CreatedAt,
	}
}

// bodyLimit is the body cap of the control plane: small for everything except the two routes that
// carry a subtitle track, which may carry up to subtitles.MaxRequestBytes, and the logo upload,
// which may carry a logo of branding.MaxBytes.
func bodyLimit(next http.Handler) http.Handler {
	small := httpx.LimitBody(maxBodyBytes)(next)
	large := httpx.LimitBody(subtitles.MaxRequestBytes)(next)
	logo := httpx.LimitBody(maxLogoRequestBytes)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/brand/logo" {
			logo.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodPost && carriesSubtitles(r.URL.Path) {
			large.ServeHTTP(w, r)
			return
		}
		small.ServeHTTP(w, r)
	})
}

// carriesSubtitles reports whether path is /v1/assets/{id}/subtitles or /v1/assets/{id}/transcripts.
func carriesSubtitles(path string) bool {
	rest, ok := strings.CutPrefix(path, "/v1/assets/")
	if !ok {
		return false
	}
	asset, tail, ok := strings.Cut(rest, "/")
	return ok && asset != "" && (tail == "subtitles" || tail == "transcripts")
}

// CreateAssetSubtitle adds a track from an uploaded WebVTT or SRT file.
func (s *server) CreateAssetSubtitle(ctx context.Context, req gen.CreateAssetSubtitleRequestObject) (gen.CreateAssetSubtitleResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.subtitleService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	meta, data, err := readSubtitleForm(req.Body)
	if err != nil {
		return nil, err
	}
	track, err := svc.AddFile(ctx, p.TenantID, actor, aid, meta, data)
	if err != nil {
		return nil, err
	}
	return gen.CreateAssetSubtitle201JSONResponse{
		Body: subtitleOut(track), Headers: gen.CreateAssetSubtitle201ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// readSubtitleForm reads the upload form. Only the four known members are accepted, each once. The
// name the client gave the file is never read.
func readSubtitleForm(mr *multipart.Reader) (subtitles.Meta, []byte, error) {
	var meta subtitles.Meta
	var data []byte
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
			return meta, nil, formError(err)
		}
		name := part.FormName()
		if i >= maxFormParts || seen[name] {
			return meta, nil, bad(name, "is sent more than once or the form has too many members")
		}
		seen[name] = true
		if name == "file" {
			if data, err = io.ReadAll(io.LimitReader(part, subtitles.MaxBytes+1)); err != nil {
				return meta, nil, formError(err)
			}
			if len(data) > subtitles.MaxBytes {
				return meta, nil, errs.New(errs.PayloadTooLarge, "The file is larger than 2 MB.")
			}
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(part, maxFormField+1))
		if err != nil {
			return meta, nil, formError(err)
		}
		if len(raw) > maxFormField {
			return meta, nil, bad(name, "is too long")
		}
		switch name {
		case "language":
			meta.Language = string(raw)
		case "label":
			meta.Label = string(raw)
		case "default":
			switch string(raw) {
			case "true":
				meta.Default = true
			case "false":
			default:
				return meta, nil, bad("default", "must be true or false")
			}
		default:
			return meta, nil, bad("form", "has a member that is not part of the request")
		}
	}
	if !seen["file"] {
		return meta, nil, bad("file", "is required")
	}
	return meta, data, nil
}

// formError maps a failure while reading the form: a body over the cap is 413, anything else is
// a malformed request.
func formError(err error) error {
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return errs.New(errs.PayloadTooLarge, "The request body is too large.")
	}
	return errs.New(errs.InvalidRequest, "The form is malformed.")
}

// ImportAssetTranscript adds a track built from timed text.
func (s *server) ImportAssetTranscript(ctx context.Context, req gen.ImportAssetTranscriptRequestObject) (gen.ImportAssetTranscriptResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.subtitleService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	meta := subtitles.Meta{Language: req.Body.Language, Label: req.Body.Label}
	if req.Body.Default != nil {
		meta.Default = *req.Body.Default
	}
	cues := make([]subtitles.TranscriptCue, len(req.Body.Cues))
	for i, c := range req.Body.Cues {
		cues[i] = subtitles.TranscriptCue{Start: c.Start, End: c.End, Text: c.Text}
		if c.Speaker != nil {
			cues[i].Speaker = *c.Speaker
		}
	}
	track, err := svc.AddTranscript(ctx, p.TenantID, actor, aid, meta, cues)
	if err != nil {
		return nil, err
	}
	return gen.ImportAssetTranscript201JSONResponse{
		Body: subtitleOut(track), Headers: gen.ImportAssetTranscript201ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// ListAssetSubtitles lists the asset's tracks.
func (s *server) ListAssetSubtitles(ctx context.Context, req gen.ListAssetSubtitlesRequestObject) (gen.ListAssetSubtitlesResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.subtitleService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	rows, err := svc.List(ctx, p.TenantID, aid)
	if err != nil {
		return nil, err
	}
	body := gen.SubtitleList{Items: make([]gen.SubtitleTrack, len(rows))}
	for i, t := range rows {
		body.Items[i] = subtitleOut(t)
	}
	return gen.ListAssetSubtitles200JSONResponse{Body: body, Headers: gen.ListAssetSubtitles200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetAssetSubtitle returns one track's metadata.
func (s *server) GetAssetSubtitle(ctx context.Context, req gen.GetAssetSubtitleRequestObject) (gen.GetAssetSubtitleResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.subtitleService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	tid, err := parseSubtitleID(req.SubtitleId)
	if err != nil {
		return nil, err
	}
	t, err := svc.Get(ctx, p.TenantID, aid, tid)
	if err != nil {
		return nil, err
	}
	return gen.GetAssetSubtitle200JSONResponse{Body: subtitleOut(t), Headers: gen.GetAssetSubtitle200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// DeleteAssetSubtitle removes a track.
func (s *server) DeleteAssetSubtitle(ctx context.Context, req gen.DeleteAssetSubtitleRequestObject) (gen.DeleteAssetSubtitleResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.subtitleService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	tid, err := parseSubtitleID(req.SubtitleId)
	if err != nil {
		return nil, err
	}
	if err := svc.Delete(ctx, p.TenantID, actor, aid, tid); err != nil {
		return nil, err
	}
	return gen.DeleteAssetSubtitle204Response{Headers: gen.DeleteAssetSubtitle204ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
