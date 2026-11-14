package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
)

// Exit codes.
const (
	exitOurs     = 0
	exitModified = 1
	exitCannot   = 2
	exitUsage    = 3
)

const (
	maxManifestBytes = 16 << 20
	maxProofBytes    = 1 << 20
	keysURLTimeout   = 10 * time.Second
)

// missingReason marks a manifest entry with no file in the directory. It counts as cannot say.
const missingReason = "missing"

type line struct {
	Path    string `json:"path"`
	Outcome string `json:"outcome"` // ours, modified, cannot_say or missing
	Reason  string `json:"reason"`
	Detail  string `json:"detail,omitempty"`
}

type jobs struct {
	file, path string // path is the manifest path
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		manifestFile = fl.String("manifest", "", "signed manifest (DSSE envelope JSON)")
		keysFile     = fl.String("keys", "", "key set JSON file")
		keysURL      = fl.String("keys-url", "", "fetch the key set from this https URL")
		variant      = fl.String("variant", proof.Original, "original or masked")
		path         = fl.String("path", "", "manifest path of the single file argument")
		root         = fl.String("root", "", "HLS root that file paths are relative to")
		proofFile    = fl.String("proof", "", "inclusion proof JSON for the single file argument")
		asJSON       = fl.Bool("json", false, "machine-readable output")
	)
	if err := fl.Parse(args); err != nil {
		return exitUsage
	}
	variantSet := false
	fl.Visit(func(f *flag.Flag) { variantSet = variantSet || f.Name == "variant" })
	usageErr := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(stderr, "cipherframe verify: "+format+"\n", a...)
		return exitUsage
	}
	switch {
	case *manifestFile == "" || fl.NArg() == 0:
		return usageErr("--manifest and at least one file are required")
	case (*keysFile == "") == (*keysURL == ""):
		return usageErr("give exactly one of --keys and --keys-url")
	case *variant != proof.Original && *variant != proof.Masked:
		return usageErr("--variant must be original or masked")
	case *proofFile != "" && (fl.NArg() != 1 || *path != "" || *root != ""):
		return usageErr("--proof takes exactly one file and no --path or --root")
	case *path != "" && fl.NArg() != 1:
		return usageErr("--path takes exactly one file")
	}
	if *keysURL != "" {
		if err := checkKeysURL(*keysURL); err != nil {
			return usageErr("%v", err)
		}
	}

	// Past this point nothing is a usage error: anything that cannot be read or fetched is
	// "cannot say", never "modified".
	var (
		lines  []line
		signed *offline.Signed
		pr     *proof.Proof
	)
	fail := func(r offline.Result) { // one line per file for a failure that affects them all
		for _, f := range fl.Args() {
			lines = append(lines, line{Path: f, Outcome: "cannot_say", Reason: string(r.Reason), Detail: r.Detail})
		}
	}
	keys, err := loadKeys(*keysFile, *keysURL)
	if err == nil {
		var env []byte
		if env, err = readLimited(*manifestFile, maxManifestBytes); err == nil {
			signed, err = offline.Open(env, keys)
		}
	}
	if err == nil && *proofFile != "" {
		pr, err = loadProof(*proofFile)
		if err == nil && variantSet && pr.Variant != *variant {
			err = fmt.Errorf("%w: --variant %s but the proof is for %s", verify.ErrMalformed, *variant, pr.Variant)
		}
	}
	if err != nil {
		fail(offline.FromError(err))
		return finish(stdout, lines, *asJSON)
	}

	var work []jobs
	switch {
	case pr != nil:
		work = []jobs{{fl.Arg(0), pr.Path}}
	case *path != "":
		work = []jobs{{fl.Arg(0), *path}}
	default:
		var missing []string
		work, missing = expand(fl.Args(), *root, signed.Paths(*variant))
		for _, m := range missing {
			lines = append(lines, line{Path: m, Outcome: missingReason, Reason: missingReason, Detail: "listed in the manifest, not in the directory"})
		}
	}
	for _, w := range work {
		sum, herr := hashFile(w.file)
		var r offline.Result
		switch {
		case herr != nil:
			r = offline.FromError(herr)
		case pr != nil:
			r = signed.Proof(*pr, sum)
		default:
			r = signed.Artifact(w.path, sum, *variant)
		}
		o := strings.ReplaceAll(r.Outcome.String(), " ", "_")
		lines = append(lines, line{Path: w.path, Outcome: o, Reason: string(r.Reason), Detail: r.Detail})
	}
	return finish(stdout, lines, *asJSON)
}

// expand turns the file and directory arguments into jobs. A directory contributes every file
// under it that the manifest lists, and each listed path with no file is returned as missing.
// A plain file is matched by its path relative to root (or as given; an absolute path without
// root by its base name).
func expand(args []string, root string, listed []string) (work []jobs, missing []string) {
	inManifest := map[string]bool{}
	for _, p := range listed {
		inManifest[p] = true
	}
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil || !st.IsDir() {
			work = append(work, jobs{a, relPath(a, root)})
			continue
		}
		seen := map[string]bool{}
		_ = filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if rel, rerr := filepath.Rel(a, p); rerr == nil && inManifest[filepath.ToSlash(rel)] {
				seen[filepath.ToSlash(rel)] = true
				work = append(work, jobs{p, filepath.ToSlash(rel)})
			}
			return nil
		})
		for _, p := range listed {
			if !seen[p] {
				missing = append(missing, p)
			}
		}
	}
	sort.Strings(missing)
	return work, missing
}

func relPath(file, root string) string {
	if root != "" {
		if rel, err := filepath.Rel(root, file); err == nil {
			return filepath.ToSlash(rel)
		}
	}
	if filepath.IsAbs(file) {
		return filepath.Base(file)
	}
	return filepath.ToSlash(filepath.Clean(file))
}

func finish(stdout io.Writer, lines []line, asJSON bool) int {
	var ours, modified, cannot, missing int
	for _, l := range lines {
		switch l.Outcome {
		case "ours":
			ours++
		case "modified":
			modified++
		case missingReason:
			missing++
		default:
			cannot++
		}
	}
	code := exitOurs
	switch {
	case modified > 0:
		code = exitModified
	case cannot+missing > 0 || len(lines) == 0:
		code = exitCannot
	}
	if asJSON {
		out := struct {
			Results []line         `json:"results"`
			Summary map[string]int `json:"summary"`
		}{lines, map[string]int{"ours": ours, "modified": modified, "cannot_say": cannot, "missing": missing}}
		if out.Results == nil {
			out.Results = []line{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return code
	}
	for _, l := range lines {
		o := strings.ReplaceAll(l.Outcome, "_", " ")
		_, _ = fmt.Fprintf(stdout, "%-11s %s  (%s)\n", o, l.Path, l.Reason+detail(l))
	}
	_, _ = fmt.Fprintf(stdout, "%d ours, %d modified, %d cannot say, %d missing\n", ours, modified, cannot, missing)
	return code
}

func detail(l line) string {
	if l.Outcome == "ours" || l.Detail == "" || l.Outcome == missingReason {
		return ""
	}
	return ": " + l.Detail
}

func hashFile(name string) ([sha256.Size]byte, error) {
	f, err := os.Open(name) //nolint:gosec // the user names the file to verify
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer func() { _ = f.Close() }()
	return offline.HashReader(f)
}

func readLimited(name string, limit int64) ([]byte, error) {
	f, err := os.Open(name) //nolint:gosec // the user names the file to verify
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readAll(f, limit)
}

func readAll(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: input larger than %d bytes", verify.ErrMalformed, limit)
	}
	return b, nil
}

func loadProof(name string) (*proof.Proof, error) {
	b, err := readLimited(name, maxProofBytes)
	if err != nil {
		return nil, err
	}
	var p proof.Proof
	if json.Unmarshal(b, &p) != nil {
		return nil, fmt.Errorf("%w: not a proof document", verify.ErrMalformed)
	}
	return &p, nil
}

func loadKeys(file, rawURL string) (offline.KeySet, error) {
	var b []byte
	var err error
	if file != "" {
		b, err = readLimited(file, offline.MaxKeySetBytes)
	} else {
		b, err = fetchKeys(rawURL)
	}
	if err != nil {
		return nil, err
	}
	return offline.ParseKeySet(b)
}

// checkKeysURL allows https, and http only for a loopback host (tests and local servers).
func checkKeysURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--keys-url is not a valid URL")
	}
	host := u.Hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme == "https" || (u.Scheme == "http" && loopback) {
		return nil
	}
	return fmt.Errorf("--keys-url must be https (http only for localhost)")
}

// fetchKeys is the only network access of the tool: one GET, 10 seconds, 1 MiB, no redirect to a
// URL that checkKeysURL would refuse.
func fetchKeys(raw string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keysURLTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: keysURLTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return checkKeysURL(r.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching the key set: HTTP %d", resp.StatusCode)
	}
	return readAll(resp.Body, offline.MaxKeySetBytes)
}
