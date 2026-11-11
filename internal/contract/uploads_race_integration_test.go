//go:build integration

package contract

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// Six clients start the tus upload of one asset at the same moment: exactly one creation wins,
// the others are refused, and the object store holds one multipart upload and one .info object.
func TestTusCreationRaceStartsOneUpload(t *testing.T) {
	e := newUpEnv(t)
	u := e.create(e.admin, 1000, "tus")
	var wg sync.WaitGroup
	statuses := make([]int, 6)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := e.tusReq(http.MethodPost, u.url, u.token, map[string]string{"Upload-Length": "1000"}, nil)
			resp, err := e.client.Do(req)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	created, refused := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("unexpected status %d", s)
		}
	}
	if created != 1 || refused != 5 {
		t.Fatalf("%d created and %d refused, want 1 and 5 (%v)", created, refused, statuses)
	}
	a := e.dbAsset(u.assetID)
	if a.State != db.AssetUploading || a.S3UploadID == "" {
		t.Fatalf("asset after the race: %+v", a)
	}
	if n := e.openMultipartUploads(a); n != 1 {
		t.Fatalf("%d open multipart uploads, want 1", n)
	}
	if objs := e.sourceObjects(a); len(objs) != 1 || objs[0] != a.SourceKey+".info" {
		t.Fatalf("objects under the source prefix: %v", objs)
	}
}

// The size limit is checked again at commit, against the limit in force then.
func TestCommitChecksTheSizeLimitAgain(t *testing.T) {
	e := newUpEnv(t)
	u := e.create(e.admin, 100, "multipart")
	e.putPart(u, 1, make([]byte, 100), 200)

	queue, err := jobs.NewQueue(e.pool, jobs.NewRegistry(), jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	strict, err := uploads.NewService(uploads.Deps{
		Pool: e.pool, Source: e.buckets.Source, Queue: queue, EdgeURL: e.edgeSrv.URL,
		Limits: uploads.Limits{MaxSourceBytes: 50, PartBytes: testPartBytes, TokenTTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	aid, _ := id.Parse[id.AssetKind](u.assetID)
	_, err = strict.Commit(context.Background(), e.tenant.ID, uploads.Actor{}, aid)
	var ee *errs.Error
	if !errors.As(err, &ee) || ee.Code != errs.PayloadTooLarge {
		t.Fatalf("commit over the lowered limit: %v, want payload_too_large", err)
	}
	if n, _ := e.processJobs(); n != 0 {
		t.Fatalf("a refused commit enqueued %d jobs", n)
	}
	e.assertState(e.admin, u.assetID, "uploading")
	e.call(e.admin, "POST", "/v1/assets/"+u.assetID+"/commit", nil, 200) // the normal limit still passes
}
