package edge

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/hls"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// Thumbnails (ADR 0046) are the poster, the sprite sheet and the WebVTT thumbnail track of the
// variant a session is bound to. They sit behind the same guard as the media playlists and are
// always streamed through this proxy, whatever the tenant's delivery mode is: they are plain images
// that show faces, so a presigned URL (which would outlive the session check) is never made for
// them. The key is built from the tenant, asset and variant of the verified token, never from the
// request, so a session bound to the masked variant cannot reach an image of the original.

// thumbnailObject opens the object at key.
func (s *server) thumbnailObject(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	rc, info, err := s.play.delivery.Get(ctx, key, nil)
	if err != nil {
		return nil, 0, storage.ToAppError(err) // not_found for an asset without thumbnails
	}
	return rc, info.Size, nil
}

// GetPlaybackPoster serves the session variant's poster.
func (s *server) GetPlaybackPoster(ctx context.Context, _ gen.GetPlaybackPosterRequestObject) (gen.GetPlaybackPosterResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	body, size, err := s.thumbnailObject(ctx, keys.VariantPoster(g.tenant, g.asset, g.variant))
	if err != nil {
		return nil, err
	}
	return gen.GetPlaybackPoster200ImagejpegResponse{
		Body: body, ContentLength: size, Headers: gen.GetPlaybackPoster200ResponseHeaders(playlistHeaders(ctx)),
	}, nil
}

// GetPlaybackSprite serves the session variant's sprite sheet.
func (s *server) GetPlaybackSprite(ctx context.Context, _ gen.GetPlaybackSpriteRequestObject) (gen.GetPlaybackSpriteResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	body, size, err := s.thumbnailObject(ctx, keys.VariantSprite(g.tenant, g.asset, g.variant))
	if err != nil {
		return nil, err
	}
	return gen.GetPlaybackSprite200ImagejpegResponse{
		Body: body, ContentLength: size, Headers: gen.GetPlaybackSprite200ResponseHeaders(playlistHeaders(ctx)),
	}, nil
}

// GetPlaybackThumbnails serves the session variant's thumbnail track, with the session's token added
// to the sprite references when the tenant allows tokens in URLs.
func (s *server) GetPlaybackThumbnails(ctx context.Context, _ gen.GetPlaybackThumbnailsRequestObject) (gen.GetPlaybackThumbnailsResponseObject, error) {
	g, err := grantOf(ctx)
	if err != nil {
		return nil, err
	}
	src, err := s.play.readPlaylist(ctx, keys.VariantThumbnails(g.tenant, g.asset, g.variant))
	if err != nil {
		return nil, err
	}
	out := hls.RewriteThumbnailTrack(src, g.urlToken)
	return gen.GetPlaybackThumbnails200TextvttResponse{
		Body: strings.NewReader(out), ContentLength: int64(len(out)), Headers: gen.GetPlaybackThumbnails200ResponseHeaders(playlistHeaders(ctx)),
	}, nil
}

func (g guarded) GetPlaybackPoster(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.GetPlaybackPosterParams) {
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackPoster(w, r, sessionID, params)
	})
}

func (g guarded) GetPlaybackSprite(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.GetPlaybackSpriteParams) {
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackSprite(w, r, sessionID, params)
	})
}

func (g guarded) GetPlaybackThumbnails(w http.ResponseWriter, r *http.Request, sessionID gen.PlaySessionId, params gen.GetPlaybackThumbnailsParams) {
	g.play.authorize(w, r, sessionID, token.ScopeManifest, func(r *http.Request) {
		g.ServerInterface.GetPlaybackThumbnails(w, r, sessionID, params)
	})
}
