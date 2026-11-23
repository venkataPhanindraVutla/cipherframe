package rekey

import (
	"errors"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
)

func TestRekeyableByState(t *testing.T) {
	for name, tc := range map[string]struct {
		asset db.Asset
		want  errs.Code // empty: allowed
	}{
		"ready":                 {db.Asset{State: db.AssetReady}, ""},
		"ready, masking ready":  {db.Asset{State: db.AssetReady, MaskFaces: true, MaskingState: db.MaskingReady}, ""},
		"ready, masking failed": {db.Asset{State: db.AssetReady, MaskFaces: true, MaskingState: db.MaskingFailed}, ""},
		"masking pending":       {db.Asset{State: db.AssetReady, MaskFaces: true, MaskingState: db.MaskingPending}, errs.Conflict},
		"masking not started":   {db.Asset{State: db.AssetReady, MaskFaces: true}, errs.Conflict},
		"processing":            {db.Asset{State: db.AssetProcessing}, errs.AssetNotReady},
		"failed":                {db.Asset{State: db.AssetFailed}, errs.AssetNotReady},
		"uploading":             {db.Asset{State: db.AssetUploading}, errs.AssetNotReady},
		"deleting":              {db.Asset{State: db.AssetDeleting}, errs.Conflict},
		"deleted":               {db.Asset{State: db.AssetDeleted}, errs.NotFound},
	} {
		err := rekeyable(tc.asset)
		var e *errs.Error
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (!errors.As(err, &e) || e.Code != tc.want):
			t.Errorf("%s: err = %v, want %s", name, err, tc.want)
		}
	}
}

func TestSameRoots(t *testing.T) {
	rends := []manifest.Rendition{{Name: "720p", MerkleRoot: "aa"}, {Name: "480p", MerkleRoot: "bb"}}
	if !sameRoots(rends, map[string]string{"720p": "aa", "480p": "bb"}) {
		t.Error("equal roots reported as changed")
	}
	for name, roots := range map[string]map[string]string{
		"changed root": {"720p": "aa", "480p": "cc"},
		"missing":      {"720p": "aa"},
		"extra":        {"720p": "aa", "480p": "bb", "360p": "dd"},
		"renamed":      {"720p": "aa", "240p": "bb"},
	} {
		if sameRoots(rends, roots) {
			t.Errorf("%s: reported as unchanged", name)
		}
	}
}

func TestArgsKindIsStable(t *testing.T) {
	if (Args{}).Kind() != "asset.rekey" {
		t.Error("the job kind changed; jobs of the old kind would be orphaned, and the purge waits for it by name")
	}
}
