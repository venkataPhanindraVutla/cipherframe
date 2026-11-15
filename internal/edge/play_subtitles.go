package edge

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Subtitle tracks (ADR 0044) are served only through a session, on the same guard as the media
// playlists: a token with the manifest scope, the session row, token_in_url and CORS. They are not
// encrypted, so the session is their only access control. The track is found by the tenant and
// asset in the token and the track ID in the path together, so a session cannot read another
// asset's track, and the object key is built from IDs, never from the request.

var reSubtitleID = regexp.MustCompile(`^sub_[0-9a-hjkmnp-tv-z]{26}$`)

// SubtitleStore is what the subtitle routes read from the database. *db.Repos implements it.
type SubtitleStore interface {
	ListSubtitles(ctx context.Context, tenantID id.TenantID, assetID id.AssetID) ([]db.Subtitle, error)
	GetSubtitle(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, trackID id.SubtitleID) (db.Subtitle, error)
}

// subtitleTracks returns the session's asset's tracks as the master playlist lists them.
func (p *Playback) subtitleTracks(ctx context.Context, g grant) ([]hls.SubtitleTrack, error) {
	if p.subtitles == nil {
		return nil, nil
	}
	rows, err := p.subtitles.ListSubtitles(ctx, g.tenant, g.asset)
	if err != nil {
		return nil, err
	}
	out := make([]hls.SubtitleTrack, len(rows))
	for i, t := range rows {
		out[i] = hls.SubtitleTrack{ID: t.ID.String(), Language: t.Language, Label: t.Label, Default: t.Default}
	}
	return out, nil
}

// track finds the track named in the path under the session's asset.
func (p *Playback) track(ctx context.Context, g grant, raw string) (db.Subtitle, error) {
	if p.subtitles == nil {
		return db.Subtitle{}, errs.New(errs.NotFound, "No such resource.")
	}
	tid, err := id.Parse[id.SubtitleKind](raw)
	if err != nil {
		return db.Subtitle{}, errs.New(errs.NotFound, "No such resource.")
	}
	t, err := p.subtitles.GetSubtitle(ctx, g.tenant, g.asset, tid)
	if err != nil {
		return db.Subtitle{}, err // not_found for an unknown track, another asset's included
	}
	return t, nil
}

// GetPlaybackSubtitleMedia serves one track's media playlist.
func (s *server) GetPlaybackSubtitleMedia(ctx context.Context, req gen.GetPlaybackSubtitleMediaRequestObject) (gen.GetPlaybackSubtitleMediaResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	t, err := s.play.track(ctx, g, req.SubtitleId)
	if err != nil {
		return nil, err
	}
	out, err := hls.RenderSubtitleMedia(time.Duration(t.DurationMS)*time.Millisecond, hls.SubtitleFileURI(g.urlToken))
	if err != nil {
		return nil, rewriteFailed(ctx, g, err)
	}
	h := playlistHeaders(ctx)
	return gen.GetPlaybackSubtitleMedia200ApplicationvndAppleMpegurlResponse{
		Body: strings.NewReader(out), ContentLength: int64(len(out)),
		Headers: gen.GetPlaybackSubtitleMedia200ResponseHeaders(h),
	}, nil
}

// GetPlaybackSubtitleFile streams one track's WebVTT file from the delivery bucket.
func (s *server) GetPlaybackSubtitleFile(ctx context.Context, req gen.GetPlaybackSubtitleFileRequestObject) (gen.GetPlaybackSubtitleFileResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	t, err := s.play.track(ctx, g, req.SubtitleId)
	if err != nil {
		return nil, err
	}
	rc, info, err := s.play.delivery.Get(ctx, keys.Subtitle(g.tenant, g.asset, t.ID), nil)
	if err != nil {
		return nil, storage.ToAppError(err)
	}
	h := playlistHeaders(ctx)
	return gen.GetPlaybackSubtitleFile200TextvttResponse{
		Body: rc, ContentLength: info.Size, Headers: gen.GetPlaybackSubtitleFile200ResponseHeaders(h),
	}, nil
}

func (g guarded) GetPlaybackSubtitleMedia(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, subtitleID gen.PlaySubtitleId, params gen.GetPlaybackSubtitleMediaParams) {
	if !reSubtitleID.MatchString(subtitleID) {
		writeAuthError(w, r, errPlaybackNotFound())
		return
	}
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackSubtitleMedia(w, r, sessionID, subtitleID, params)
	})
}

func (g guarded) GetPlaybackSubtitleFile(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, subtitleID gen.PlaySubtitleId, params gen.GetPlaybackSubtitleFileParams) {
	if !reSubtitleID.MatchString(subtitleID) {
		writeAuthError(w, r, errPlaybackNotFound())
		return
	}
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackSubtitleFile(w, r, sessionID, subtitleID, params)
	})
}
