package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

// runTranscode uploads a file --jobs times (--concurrency at a time) and times each asset from its
// commit to the ready state. The clip is small, so the upload is one PATCH.
func runTranscode(ctx context.Context, args []string) error {
	var c common
	var file string
	var jobs, conc int
	var mediaSecs float64
	var timeout time.Duration
	var keep bool
	fs := flag.NewFlagSet("transcode", flag.ContinueOnError)
	c.register(fs)
	fs.StringVar(&file, "file", "", "video file to upload")
	fs.Float64Var(&mediaSecs, "media-seconds", 0, "duration of the file in seconds")
	fs.IntVar(&jobs, "jobs", 4, "uploads to make")
	fs.IntVar(&conc, "concurrency", 1, "uploads in flight at once")
	fs.DurationVar(&timeout, "timeout", 10*time.Minute, "give up on one asset after this long")
	fs.BoolVar(&keep, "keep", false, "keep the assets (default: delete them afterwards)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if file == "" || mediaSecs <= 0 || jobs < 1 || conc < 1 {
		return errors.New("need --file, --media-seconds > 0, --jobs >= 1 and --concurrency >= 1")
	}
	data, err := os.ReadFile(file) //nolint:gosec // the operator names the file to upload
	if err != nil || len(data) == 0 {
		return errors.New("cannot read a non-empty --file")
	}
	if err := c.setup(); err != nil {
		return err
	}
	col, closer, err := newCollector(c.rawPath, c.rawSample)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	col.counting.Store(true)

	start := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var mu sync.Mutex
	var secs []float64
	for j := 1; j <= jobs; j++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if d, ok := c.transcodeJob(ctx, col, j, data, timeout, keep); ok {
				mu.Lock()
				secs = append(secs, d.Seconds())
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start).Seconds()
	sort.Float64s(secs)
	rows := summarize(1, conc, wall, col.take())
	for _, r := range rows {
		if r.Kind == "transcode" {
			fmt.Printf("jobs %d ok %d concurrency %d: commit to ready p50 %.1f s p95 %.1f s p99 %.1f s\n",
				jobs, len(secs), conc, r.P50/1000, r.P95/1000, r.P99/1000)
		}
	}
	// Throughput over the span in which jobs ran, uploads included in the wall time.
	fmt.Printf("media %.0f s per job, %d jobs finished in %.1f s wall: %.2f media seconds per wall second\n",
		mediaSecs, len(secs), wall, float64(len(secs))*mediaSecs/wall)
	if c.summaryPath != "" {
		if err := writeSummary(c.summaryPath, rows); err != nil {
			return err
		}
	}
	if len(secs) < jobs {
		return fmt.Errorf("%d of %d jobs failed", jobs-len(secs), jobs)
	}
	return nil
}

// transcodeJob runs one upload and wait. It records an upload and a transcode row.
func (c *common) transcodeJob(ctx context.Context, col *collector, id int, data []byte, timeout time.Duration, keep bool) (time.Duration, bool) {
	ct := "video/mp4"
	resp, err := c.client.CreateAsset(ctx, apiclient.CreateAssetRequest{ //nolint:bodyclose // decode closes it
		UploadMethod: apiclient.UploadMethod("tus"), SizeBytes: int64(len(data)), ContentType: &ct,
	})
	var created apiclient.CreatedAsset
	if err := decode(resp, err, &created); err != nil {
		col.record(id, "upload", 0, 0)
		return 0, false
	}
	assetID := created.Asset.Id
	defer func() {
		if !keep {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if r, err := c.client.DeleteAsset(dctx, assetID); err == nil {
				_ = r.Body.Close()
			}
		}
	}()
	t := time.Now()
	status := c.tus(ctx, created.Upload, data)
	if status == http.StatusNoContent {
		resp, err = c.client.CommitAsset(ctx, assetID)
		if err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
		}
	}
	col.record(id, "upload", status, time.Since(t))
	if status/100 != 2 {
		return 0, false
	}
	// Poll from the moment the commit returned. The poll interval bounds the timing error.
	t = time.Now()
	for time.Since(t) < timeout && ctx.Err() == nil {
		var a apiclient.Asset
		resp, err := c.client.GetAsset(ctx, assetID) //nolint:bodyclose // decode closes it
		if decode(resp, err, &a) == nil {
			switch a.State {
			case apiclient.AssetStateReady:
				d := time.Since(t)
				col.record(id, "transcode", 200, d)
				return d, true
			case apiclient.AssetStateFailed:
				col.record(id, "transcode", 500, time.Since(t))
				return 0, false
			}
		}
		sleepCtx(ctx, 250*time.Millisecond)
	}
	col.record(id, "transcode", 0, time.Since(t))
	return 0, false
}

// tus creates the upload and sends all bytes in one PATCH; it returns the last status (204 on success).
func (c *common) tus(ctx context.Context, inst apiclient.UploadInstructions, data []byte) int {
	// do returns the status (0 on a transport error) and the Location header.
	do := func(method, target string, body []byte, hdr map[string]string) (int, string) {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
		if err != nil {
			return 0, ""
		}
		req.Header.Set("Authorization", "Bearer "+inst.Token)
		req.Header.Set("Tus-Resumable", "1.0.0")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.hc.Do(req) //nolint:gosec // the URL is the one the API returned
		if err != nil {
			return 0, ""
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location")
	}
	st, l := do(http.MethodPost, inst.Url, nil, map[string]string{"Upload-Length": strconv.Itoa(len(data))})
	if st != http.StatusCreated {
		return st
	}
	base, err := url.Parse(inst.Url)
	if err != nil {
		return 0
	}
	loc, err := base.Parse(l)
	if err != nil || loc.Host != base.Host {
		return 0
	}
	st, _ = do(http.MethodPatch, loc.String(), data, map[string]string{"Content-Type": "application/offset+octet-stream", "Upload-Offset": "0"})
	return st
}
