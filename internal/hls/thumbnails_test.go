package hls

import "testing"

func TestRewriteThumbnailTrack(t *testing.T) {
	vtt := "WEBVTT\n\n00:00:00.000 --> 00:00:10.000\nsprite.jpg#xywh=0,0,160,90\n\n00:00:10.000 --> 00:00:14.000\nsprite.jpg#xywh=160,0,160,90\n"
	if got := RewriteThumbnailTrack(vtt, ""); got != vtt {
		t.Errorf("no token must leave the track as it is:\n%s", got)
	}
	got := RewriteThumbnailTrack(vtt, "a b+c")
	want := "WEBVTT\n\n00:00:00.000 --> 00:00:10.000\nsprite.jpg?t=a+b%2Bc#xywh=0,0,160,90\n\n00:00:10.000 --> 00:00:14.000\nsprite.jpg?t=a+b%2Bc#xywh=160,0,160,90\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
