package id

import "testing"

func FuzzParse(f *testing.F) {
	valid := New[AssetKind]().String()
	for _, s := range []string{
		"", "ast_", valid, "ast_0000000000000000000000000g", "ast_zzzzzzzzzzzzzzzzzzzzzzzzzw",
		"cli_" + valid[4:], "AST_" + valid[4:], "ast_" + valid[4:] + "\x00", "ast_\xff\xfe",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := Parse[AssetKind](s)
		if err != nil {
			return
		}
		if got := v.String(); got != s {
			t.Fatalf("accepted %q but re-encodes to %q", s, got)
		}
		if v.IsZero() {
			t.Fatalf("accepted zero ID %q", s)
		}
	})
}

func FuzzParseSession(f *testing.F) {
	s, _ := NewSession()
	valid := s.String()
	for _, in := range []string{
		"", "ses_", valid, "ses_" + valid[4:] + "0", "SES_" + valid[4:], "ses_\xff",
		"ses_00000000000000000000000000000000000000000000000000001",
	} {
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		v, err := ParseSession(in)
		if err != nil {
			return
		}
		if got := v.String(); got != in {
			t.Fatalf("accepted %q but re-encodes to %q", in, got)
		}
	})
}
