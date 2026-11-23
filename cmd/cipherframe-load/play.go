package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/apiclient"
)

type playConfig struct {
	common
	asset, delivery, edge     string
	rendition                 string
	start, step, maxViewers   int
	stepDur, settle, p99Limit time.Duration
	maxErrRate, speed         float64
	runTag                    string
	col                       *collector
	wg                        sync.WaitGroup
	edgeBase                  *url.URL
}

func runPlay(ctx context.Context, args []string) error {
	var c playConfig
	fs := flag.NewFlagSet("play", flag.ContinueOnError)
	c.register(fs)
	fs.StringVar(&c.asset, "asset", "", "ready asset to play")
	fs.StringVar(&c.delivery, "delivery", "proxy", "proxy or presigned (sets the tenant's delivery setting for the run)")
	fs.StringVar(&c.edge, "edge", "", "edge base URL that replaces the origin of the manifest URL (default: as returned)")
	fs.StringVar(&c.rendition, "rendition", "", "play the first rendition whose playlist path contains this, such as 720p (default: the first listed)")
	fs.IntVar(&c.start, "start", 10, "viewers in the first step")
	fs.IntVar(&c.step, "step", 10, "viewers added per step")
	fs.IntVar(&c.maxViewers, "max", 200, "most viewers")
	fs.DurationVar(&c.stepDur, "step-duration", 60*time.Second, "measured time of each step")
	fs.DurationVar(&c.settle, "settle", 10*time.Second, "time after adding viewers that is not measured")
	fs.DurationVar(&c.p99Limit, "p99-limit", time.Second, "stop when segment p99 latency exceeds this")
	fs.Float64Var(&c.maxErrRate, "max-errors", 0.01, "stop when the error rate exceeds this fraction")
	fs.Float64Var(&c.speed, "speed", 1, "play this many times faster than real time (segment pace only; heartbeats keep the advertised interval)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.asset == "" || (c.delivery != "proxy" && c.delivery != "presigned") || c.speed <= 0 || len(rampTargets(c.start, c.step, c.maxViewers)) == 0 {
		return errors.New("need --asset, --delivery proxy|presigned, --speed > 0 and a ramp with --start <= --max and --step > 0")
	}
	if err := c.setup(); err != nil {
		return err
	}
	if c.edge != "" {
		u, err := url.Parse(c.edge)
		if err != nil || u.Host == "" {
			return errors.New("--edge is not a URL")
		}
		c.edgeBase = u
	}
	var tag [4]byte
	_, _ = rand.Read(tag[:])
	c.runTag = hex.EncodeToString(tag[:])
	col, closer, err := newCollector(c.rawPath, c.rawSample)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	c.col = col
	if err := c.setDelivery(ctx); err != nil {
		return err
	}

	vctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var rows []row
	viewers, lastGood := 0, 0
	for i, target := range rampTargets(c.start, c.step, c.maxViewers) {
		add := target - viewers
		for j := range add { // spread the new viewers over the settle time
			c.wg.Add(1)
			go c.viewer(vctx, viewers+j+1)
			select {
			case <-ctx.Done():
			case <-time.After(c.settle / time.Duration(add+1)):
			}
		}
		viewers = target
		c.col.counting.Store(false)
		c.col.take()
		sleepCtx(ctx, c.settle)
		c.col.counting.Store(true)
		t0 := time.Now()
		sleepCtx(ctx, c.stepDur)
		c.col.counting.Store(false)
		if ctx.Err() != nil {
			break
		}
		r := summarize(i+1, viewers, time.Since(t0).Seconds(), c.col.take())
		rows = append(rows, r...)
		all, seg := r[len(r)-1], row{}
		for _, x := range r {
			if x.Kind == "segment" {
				seg = x
			}
		}
		fmt.Printf("step %d viewers %d req/s %.1f segment p50 %.0f p95 %.0f p99 %.0f ms errors %.2f%%\n",
			i+1, viewers, all.ReqPerSec, seg.P50, seg.P95, seg.P99, 100*all.errRate())
		if why := breach(r, c.p99Limit, c.maxErrRate); why != "" {
			fmt.Printf("stopping at %d viewers: %s\n", viewers, why)
			break
		}
		lastGood = viewers
	}
	cancel()
	c.wg.Wait()
	fmt.Printf("highest passing step: %d viewers (delivery %s, speed %gx)\n", lastGood, c.delivery, c.speed)
	if c.summaryPath != "" {
		return writeSummary(c.summaryPath, rows)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// setDelivery replaces the tenant's playback settings with the same values and the chosen delivery.
func (c *playConfig) setDelivery(ctx context.Context) error {
	resp, err := c.client.GetPlaybackSettings(ctx) //nolint:bodyclose // decode closes it
	var cur map[string]any
	if err := decode(resp, err, &cur); err != nil {
		return err
	}
	delete(cur, "updated_at")
	cur["delivery"] = c.delivery
	body, _ := json.Marshal(cur)
	resp, err = c.client.UpdatePlaybackSettingsWithBody(ctx, "application/json", bytes.NewReader(body)) //nolint:bodyclose // decode closes it
	return decode(resp, err, nil)
}

// player is one virtual viewer. Its token and session URLs stay in this struct and are never printed.
type player struct {
	c       *playConfig
	id      int
	token   string
	urlMode bool
	master  *url.URL
	// mediaURL is the first rendition's media playlist; hbEvery the advertised heartbeat interval.
	mediaURL string
	hbEvery  time.Duration
}

func (c *playConfig) viewer(ctx context.Context, id int) {
	defer c.wg.Done()
	p := &player{c: c, id: id}
	for ctx.Err() == nil {
		if p.create(ctx) {
			break
		}
		sleepCtx(ctx, time.Second)
	}
	if ctx.Err() != nil {
		return
	}
	p.play(ctx)
	// End the session even though the run is over.
	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	p.do(ectx, "end", http.MethodPost, p.sibling("end"))
}

// create opens the session; it reports whether it worked. Failures are recorded as session_create errors.
func (p *player) create(ctx context.Context) bool {
	t := time.Now()
	resp, err := p.c.client.CreatePlaybackSession(ctx, apiclient.CreatePlaybackSessionRequest{ //nolint:bodyclose // decode closes it
		AssetId: p.c.asset, ViewerId: fmt.Sprintf("load-%s-%d", p.c.runTag, p.id),
	})
	var s apiclient.CreatedPlaybackSession
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	err = decode(resp, err, &s)
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		p.c.col.record(p.id, "session_create", status, time.Since(t))
		return false
	}
	p.c.col.record(p.id, "session_create", status, time.Since(t))
	m, err := url.Parse(s.ManifestUrl)
	if err != nil {
		return false
	}
	if p.c.edgeBase != nil {
		m.Scheme, m.Host = p.c.edgeBase.Scheme, p.c.edgeBase.Host
	}
	p.token, p.urlMode = s.Token, s.TokenTransport == apiclient.Url
	m.RawQuery = ""
	p.master = m
	p.hbEvery = time.Duration(max(s.HeartbeatIntervalSeconds, 1)) * time.Second
	return true
}

func (p *player) sibling(name string) string {
	u, _ := p.master.Parse(name)
	return u.String()
}

// do makes one request, with the token only on the session's own edge host, and records it. It
// returns the body for playlists and the key, nil for others (discarded), and the status.
func (p *player) do(ctx context.Context, kind, method, target string) ([]byte, int) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, 0
	}
	if u.Host == p.master.Host {
		if p.urlMode {
			q := u.Query()
			q.Set("t", p.token)
			u.RawQuery = q.Encode()
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, 0
	}
	if u.Host == p.master.Host && !p.urlMode {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	t := time.Now()
	resp, err := p.c.hc.Do(req)
	status := 0
	var body []byte
	if err == nil {
		status = resp.StatusCode
		if kind == "segment" || kind == "init" {
			_, err = io.Copy(io.Discard, resp.Body)
		} else {
			body, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		}
		_ = resp.Body.Close()
		if err != nil {
			status = 0
		}
	}
	if ctx.Err() == nil {
		p.c.col.record(p.id, kind, status, time.Since(t))
	}
	return body, status
}

// hls is what a viewer needs from a media playlist.
type hls struct {
	init, key string
	segs      []string
	durs      []time.Duration
}

// parseMaster returns the media playlist URI of the first rendition whose URI contains want (any
// rendition when want is empty), or "".
func parseMaster(b []byte, want string) string {
	for l := range strings.SplitSeq(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") && strings.Contains(l, want) {
			return l
		}
	}
	return ""
}

func attrURI(line string) string {
	_, rest, ok := strings.Cut(line, `URI="`)
	if !ok {
		return ""
	}
	u, _, _ := strings.Cut(rest, `"`)
	return u
}

func parseMedia(b []byte) hls {
	var h hls
	var d time.Duration
	for l := range strings.SplitSeq(string(b), "\n") {
		switch l = strings.TrimSpace(l); {
		case strings.HasPrefix(l, "#EXT-X-MAP:"):
			h.init = attrURI(l)
		case strings.HasPrefix(l, "#EXT-X-KEY:"):
			h.key = attrURI(l)
		case strings.HasPrefix(l, "#EXTINF:"):
			s, _, _ := strings.Cut(strings.TrimPrefix(l, "#EXTINF:"), ",")
			f, _ := strconv.ParseFloat(s, 64)
			d = time.Duration(f * float64(time.Second))
		case l != "" && !strings.HasPrefix(l, "#"):
			h.segs, h.durs = append(h.segs, l), append(h.durs, d)
		}
	}
	return h
}

func (p *player) resolve(base *url.URL, ref string) string {
	u, err := base.Parse(ref)
	if err != nil {
		return ""
	}
	return u.String()
}

// fetchMedia gets the master and one rendition's media playlist.
func (p *player) fetchMedia(ctx context.Context, withMaster bool) (hls, string) {
	if withMaster {
		b, st := p.do(ctx, "master", http.MethodGet, p.master.String())
		if st != http.StatusOK {
			return hls{}, ""
		}
		p.mediaURL = p.resolve(p.master, parseMaster(b, p.c.rendition))
	}
	b, st := p.do(ctx, "media", http.MethodGet, p.mediaURL)
	if st != http.StatusOK {
		return hls{}, ""
	}
	return parseMedia(b), p.mediaURL
}

func (p *player) heartbeat(ctx context.Context) {
	b, st := p.do(ctx, "heartbeat", http.MethodPost, p.sibling("heartbeat"))
	var r struct {
		Token    string `json:"token"`
		Interval int    `json:"heartbeat_interval_seconds"`
	}
	if st == http.StatusOK && json.Unmarshal(b, &r) == nil && r.Token != "" {
		p.token = r.Token
		p.hbEvery = time.Duration(max(r.Interval, 1)) * time.Second
	}
}

// play does what the player does: playlists, key, init segment, then one segment per segment
// duration (divided by --speed), looping over the clip, and a heartbeat at the advertised interval.
func (p *player) play(ctx context.Context) {
	h, murl := p.fetchMedia(ctx, true)
	for len(h.segs) == 0 {
		if ctx.Err() != nil {
			return
		}
		sleepCtx(ctx, time.Second)
		h, murl = p.fetchMedia(ctx, true)
	}
	base, _ := url.Parse(murl)
	if h.key != "" {
		p.do(ctx, "key", http.MethodGet, p.resolve(base, h.key))
	}
	if h.init != "" {
		p.do(ctx, "init", http.MethodGet, p.resolve(base, h.init))
	}
	// A random phase keeps the viewers from fetching their segments in lockstep.
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(h.durs[0]/time.Millisecond)+1))
	next := time.NewTimer(time.Duration(n.Int64()) * time.Millisecond)
	hb := time.NewTimer(p.hbEvery)
	defer next.Stop()
	defer hb.Stop()
	for i := 0; ; {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			p.heartbeat(ctx)
			hb.Reset(p.hbEvery)
		case <-next.C:
			p.do(ctx, "segment", http.MethodGet, p.resolve(base, h.segs[i]))
			next.Reset(time.Duration(float64(h.durs[i]) / p.c.speed))
			if i++; i == len(h.segs) { // end of the clip: play it again, with fresh playlist URLs
				i = 0
				if nh, _ := p.fetchMedia(ctx, false); len(nh.segs) > 0 {
					h = nh
				}
			}
		}
	}
}
