//go:build integration

package contract

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// dbText returns every row of every table of the database as text, for scans.
func (e *upEnv) dbText() string {
	e.t.Helper()
	ctx := context.Background()
	rows, err := e.pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		e.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			e.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	var sb strings.Builder
	for _, tbl := range tables {
		rs, err := e.pool.Query(ctx, fmt.Sprintf(`SELECT t::text FROM %s t`, pgx.Identifier{tbl}.Sanitize()))
		if err != nil {
			e.t.Fatal(err)
		}
		for rs.Next() {
			var row string
			if err := rs.Scan(&row); err != nil {
				e.t.Fatal(err)
			}
			sb.WriteString(row)
			sb.WriteByte('\n')
		}
		rs.Close()
	}
	return sb.String()
}

// storedText returns every object key, and the content of every object of at most 64 KiB, of both
// buckets.
func (e *upEnv) storedText() string {
	e.t.Helper()
	ctx := context.Background()
	var sb strings.Builder
	for _, store := range []storage.Store{e.buckets.Source, e.buckets.Delivery} {
		for o, err := range storage.ListAll(ctx, store, "") {
			if err != nil {
				e.t.Fatal(err)
			}
			sb.WriteString(o.Key + "\n")
			if o.Size > 64<<10 {
				continue
			}
			rc, _, err := store.Get(ctx, o.Key, nil)
			if err != nil {
				e.t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			sb.Write(b)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// The original file name is never stored (ADR 0040): a tus client's Upload-Metadata (which tus
// clients fill with the file name) is dropped before tusd writes its .info object, a multipart
// part's file name headers are ignored, and the API accepts no file name at all. Nothing of it
// reaches the database, the object store (keys or contents), the logs or the API's answers.
func TestOriginalFileNameIsNeverStored(t *testing.T) {
	e := newUpEnv(t)
	key := e.admin
	const name = "holiday-secret-name.mp4"
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	meta := strings.Join([]string{
		"filename " + enc(name), "name " + enc(name), "relativePath " + enc("/home/me/"+name),
		"filetype " + enc("text/html"), "secret " + enc("hunter2"),
	}, ",")
	data := make([]byte, 1000)

	// tus, with the file name in every metadata key tus clients use.
	tu := e.create(key, int64(len(data)), "tus")
	status, loc, _ := e.tusCreate(tu, int64(len(data)), meta)
	if status != http.StatusCreated {
		t.Fatalf("tus create: status %d", status)
	}
	if st, _ := e.tusPatch(loc, tu.token, 0, data); st != http.StatusNoContent {
		t.Fatalf("tus patch: status %d", st)
	}
	tuAsset := e.dbAsset(tu.assetID)
	var info struct {
		MetaData map[string]string
	}
	if err := json.Unmarshal([]byte(e.sourceObjectByKey(tuAsset.SourceKey+".info")), &info); err != nil {
		t.Fatal(err)
	}
	// The only metadata is the content type the API caller declared; nothing the client sent.
	if len(info.MetaData) != 1 || info.MetaData["filetype"] != "video/mp4" {
		t.Fatalf("the .info object holds client metadata: %v", info.MetaData)
	}
	e.call(key, "POST", "/v1/assets/"+tu.assetID+"/commit", nil, 200)

	// multipart, with the usual file name headers on the part.
	mp := e.create(key, int64(len(data)), "multipart")
	req := e.newReq("PUT", e.edgeSrv.URL, "/v1/uploads/multipart/"+mp.assetID+"/parts/1", map[string]string{
		"Authorization": "Bearer " + mp.token, "Content-Type": "application/octet-stream",
		"Content-Disposition": `attachment; filename="` + name + `"`, "X-File-Name": name,
	}, data)
	if ex, _ := e.send(req, data, true); ex.resp.StatusCode != http.StatusOK {
		t.Fatalf("multipart part: status %d: %s", ex.resp.StatusCode, ex.body)
	}
	e.call(key, "POST", "/v1/assets/"+mp.assetID+"/commit", nil, 200)

	// The API has no file name member: one sent anyway (the request is outside the spec, so it is
	// sent without request validation) is ignored, never stored.
	raw := []byte(`{"size_bytes":10,"upload_method":"tus","filename":"` + name + `","title":"` + name + `"}`)
	req = e.newReq("POST", e.apiSrv.URL, "/v1/assets", map[string]string{"Authorization": "Bearer " + key, "Content-Type": "application/json"}, raw)
	if ex, _ := e.send(req, raw, false); ex.resp.StatusCode != http.StatusCreated {
		t.Fatalf("create with a file name: status %d: %s", ex.resp.StatusCode, ex.body)
	}

	needles := []string{name, "holiday-secret", enc(name), enc("/home/me/" + name), "hunter2", enc("hunter2"), "text/html", "relativePath"}
	scans := map[string]string{"database": e.dbText(), "storage": e.storedText(), "logs": e.logs.String()}
	for where, text := range scans {
		for _, n := range needles {
			if strings.Contains(text, n) {
				t.Errorf("%q reached the %s", n, where)
			}
		}
	}
	// Positive controls: the scans do read what they should, so a miss means something.
	if !strings.Contains(scans["database"], tu.assetID) || !strings.Contains(scans["storage"], tuAsset.SourceKey+".info") ||
		!strings.Contains(scans["storage"], "video/mp4") || scans["logs"] == "" {
		t.Error("a scan did not see the data it is meant to cover")
	}
	// Nor does any response, including the refusals, repeat it.
	for _, ex := range e.rec.snapshot() {
		for _, n := range needles {
			if strings.Contains(ex.text, n) {
				t.Errorf("%s: a response holds %q", ex.label, n)
			}
		}
	}
}
