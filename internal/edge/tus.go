package edge

import (
	"io"
	"net/http"
	"strings"

	"github.com/tus/tusd/v2/pkg/handler"
	"golang.org/x/exp/slog"

	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// TusMount is the path prefix the tusd handler is mounted at. The tus endpoints are documented in
// spec/openapi.yaml under the `tus` tag but are not generated: tusd serves them.
const TusMount = "/v1/uploads/tus/"

// newTus builds the tusd handler behind the upload-token check. Termination, concatenation,
// deferred length and download are all off: the only operations are creation, offset and chunk
// (aborting goes through the API, and the source is never read back through edge). tusd's own
// logging is discarded: Cipherframe's access log records the route and status, and tusd's lines
// include request paths and upload IDs.
func newTus(up *Uploads) (http.Handler, error) {
	composer := handler.NewStoreComposer()
	up.Tus.UseIn(composer)
	up.Locker.UseIn(composer)

	base := TusMount
	if up.PublicURL != "" {
		base = up.PublicURL + TusMount
	}
	h, err := handler.NewHandler(handler.Config{
		StoreComposer:           composer,
		BasePath:                base,
		MaxSize:                 up.Limits.MaxSourceBytes,
		DisableDownload:         true,
		DisableTermination:      true,
		DisableConcatenation:    true,
		PreUploadCreateCallback: up.Tus.PreCreate,
		Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return nil, err
	}
	return up.tusAuth(http.StripPrefix(strings.TrimSuffix(TusMount, "/"), h)), nil
}

// tusAuth checks the upload token before tusd sees a request, and that the upload named in the
// URL is the token's own asset. A CORS preflight carries no Authorization header by design, so
// OPTIONS goes straight to tusd, which answers it without touching any upload.
func (u *Uploads) tusAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		g, err := u.authorize(r)
		if err != nil {
			writeAuthError(w, r, err)
			return
		}
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(TusMount, "/")), "/")
		if rest != "" && rest != g.Asset.ID.String() {
			httpx.WriteProblem(w, r, errs.New(errs.NotFound, "No such upload."))
			return
		}
		next.ServeHTTP(w, r.WithContext(uploads.WithGrant(r.Context(), g)))
	})
}

// tusUnavailable answers when the process runs without the upload machinery.
func tusUnavailable() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, errUnavailable())
	})
}
