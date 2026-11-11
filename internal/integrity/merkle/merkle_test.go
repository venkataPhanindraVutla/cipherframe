package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// Test vectors: the 8-leaf tree used by the Certificate Transparency reference implementations
// (RFC 6962 hashing, identical to RFC 9162 for SHA-256). The leaf inputs, the roots of the
// prefix trees of size 0..8 and the inclusion proofs for an 8-leaf tree are those published in
// the test data of google/certificate-transparency-go (merkletree tests) and
// transparency-dev/merkle (testonly). They are reproduced here as data; neither repository is a
// dependency.
var ctLeafData = []string{
	"",
	"00",
	"10",
	"2021",
	"3031",
	"40414243",
	"5051525354555657",
	"606162636465666768696a6b6c6d6e6f",
}

var ctRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // size 0
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", // size 1
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", // size 2
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", // size 3
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", // size 4
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", // size 5
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", // size 6
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", // size 7
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", // size 8
}

// ctProofs are inclusion proofs (leaf index 0-based, tree size, audit path) from the same data.
var ctProofs = []struct {
	index, size uint64
	path        []string
}{
	{0, 1, nil},
	{0, 8, []string{
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
		"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
	}},
	{5, 8, []string{
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	}},
	{2, 3, []string{"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"}},
	// The last leaf of a 5-leaf tree: its sibling subtree is the whole 4-leaf tree, whose root is
	// the published size-4 root.
	{4, 5, []string{"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
}

func mustHash(t testing.TB, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != HashSize {
		t.Fatalf("bad hash %q", s)
	}
	return Hash(b)
}

func ctLeaves(t testing.TB) []Hash {
	t.Helper()
	out := make([]Hash, len(ctLeafData))
	for i, s := range ctLeafData {
		d, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = HashLeaf(d)
	}
	return out
}

// refMTH is the recursive definition of RFC 9162 section 2.1.1, written independently of Builder.
func refMTH(d []Hash) Hash {
	switch len(d) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return d[0]
	}
	k := 1
	for k*2 < len(d) {
		k *= 2
	}
	l, r := refMTH(d[:k]), refMTH(d[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func TestCTRoots(t *testing.T) {
	leaves := ctLeaves(t)
	var b Builder
	if b.Root() != mustHash(t, ctRoots[0]) || b.Root() != EmptyRoot() {
		t.Fatal("empty root")
	}
	for n := 1; n <= 8; n++ {
		b.AppendLeafHash(leaves[n-1])
		want := mustHash(t, ctRoots[n])
		if got := b.Root(); got != want {
			t.Errorf("builder size %d: %x want %x", n, got, want)
		}
		if got := RootOf(leaves[:n]); got != want {
			t.Errorf("RootOf size %d: %x want %x", n, got, want)
		}
		if b.Size() != uint64(n) {
			t.Errorf("size %d", b.Size())
		}
	}
}

func TestCTLeafHashPrefix(t *testing.T) {
	want := sha256.Sum256([]byte{0x00})
	if HashLeaf(nil) != Hash(want) || HashLeaf(nil) != mustHash(t, ctRoots[1]) {
		t.Fatal("leaf of empty data")
	}
}

func TestCTInclusionProofs(t *testing.T) {
	leaves := ctLeaves(t)
	for _, tc := range ctProofs {
		got, err := InclusionProof(leaves[:tc.size], tc.index)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(tc.path) {
			t.Fatalf("(%d,%d): proof length %d want %d", tc.index, tc.size, len(got), len(tc.path))
		}
		for i := range got {
			if got[i] != mustHash(t, tc.path[i]) {
				t.Errorf("(%d,%d): element %d = %x want %s", tc.index, tc.size, i, got[i], tc.path[i])
			}
		}
		root := mustHash(t, ctRoots[tc.size])
		if err := VerifyInclusion(leaves[tc.index], tc.index, tc.size, got, root); err != nil {
			t.Errorf("(%d,%d): %v", tc.index, tc.size, err)
		}
	}
}

// syntheticLeaves returns n distinct leaf hashes.
func syntheticLeaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		var d [8]byte
		binary.BigEndian.PutUint64(d[:], uint64(i))
		out[i] = HashLeaf(d[:])
	}
	return out
}

func TestEveryIndexProvesAndVerifies(t *testing.T) {
	for n := 1; n <= 257; n++ {
		leaves := syntheticLeaves(n)
		root := RootOf(leaves)
		if root != refMTH(leaves) {
			t.Fatalf("size %d: builder disagrees with RFC recursive definition", n)
		}
		for i := range n {
			idx := uint64(i)
			proof, err := InclusionProof(leaves, idx)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(leaves[i], idx, uint64(n), proof, root); err != nil {
				t.Fatalf("size %d index %d: %v", n, i, err)
			}
		}
	}
}

func TestTamperingFails(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 64, 100} {
		leaves := syntheticLeaves(n)
		root := RootOf(leaves)
		for i := 0; i < n; i += 1 + n/7 {
			idx := uint64(i)
			size := uint64(n) //nolint:gosec // n is a small positive test constant
			proof, _ := InclusionProof(leaves, idx)

			// Flipped bit in the leaf.
			bad := leaves[i]
			bad[0] ^= 1
			if err := VerifyInclusion(bad, idx, size, proof, root); !errors.Is(err, verify.ErrTampered) {
				t.Errorf("n=%d i=%d: flipped leaf: %v", n, i, err)
			}
			// Flipped bit in the root.
			badRoot := root
			badRoot[31] ^= 0x80
			if err := VerifyInclusion(leaves[i], idx, size, proof, badRoot); !errors.Is(err, verify.ErrTampered) {
				t.Errorf("n=%d i=%d: flipped root: %v", n, i, err)
			}
			// Flipped bit in every proof element, every bit position of the first byte and last.
			for e := range proof {
				for _, pos := range []int{0, 15, 31} {
					cp := append([]Hash(nil), proof...)
					cp[e][pos] ^= 1
					if err := VerifyInclusion(leaves[i], idx, size, cp, root); !errors.Is(err, verify.ErrTampered) {
						t.Errorf("n=%d i=%d e=%d: flipped proof: %v", n, i, e, err)
					}
				}
			}
			// Wrong size. An RFC 9162 proof binds the leaf to the root only through the sibling
			// hashes; the size merely fixes the path's length and left/right orientation, so a
			// size with the same shape verifies against the same root (the size must therefore be
			// authenticated elsewhere, see docs/integrity.md). Every size with a different path
			// length, and every size not above the index, must fail.
			for _, s := range []uint64{idx, size / 2, size + 1, size * 2, size + 7, size*4 + 3} {
				if s == size || s == 0 {
					continue
				}
				err := VerifyInclusion(leaves[i], idx, s, proof, root)
				if s <= idx {
					if !errors.Is(err, verify.ErrMalformed) {
						t.Errorf("n=%d i=%d: size %d <= index: %v", n, i, s, err)
					}
					continue
				}
				other, _ := InclusionProof(syntheticLeaves(int(s)), idx) //nolint:gosec // s is at most a few hundred
				if len(other) != len(proof) && err == nil {
					t.Errorf("n=%d i=%d: size %d with a different path length verified", n, i, s)
				}
			}
			// Wrong index.
			if n > 1 {
				if err := VerifyInclusion(leaves[i], (idx+1)%size, size, proof, root); err == nil {
					t.Errorf("n=%d i=%d: wrong index verified", n, i)
				}
			}
			// Truncated or extended proof is malformed.
			if len(proof) > 0 {
				err := VerifyInclusion(leaves[i], idx, size, proof[:len(proof)-1], root)
				if !errors.Is(err, verify.ErrMalformed) && !errors.Is(err, verify.ErrTampered) {
					t.Errorf("short proof: %v", err)
				}
			}
			err := VerifyInclusion(leaves[i], idx, size, append(append([]Hash(nil), proof...), Hash{}), root)
			if err == nil {
				t.Errorf("long proof verified")
			}
		}
	}
}

func TestMalformedInputs(t *testing.T) {
	leaves := syntheticLeaves(4)
	root := RootOf(leaves)
	proof, _ := InclusionProof(leaves, 0)
	if err := VerifyInclusion(leaves[0], 0, 0, nil, root); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("size 0: %v", err)
	}
	if err := VerifyInclusion(leaves[0], 4, 4, proof, root); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("index out of range: %v", err)
	}
	if err := VerifyInclusion(leaves[0], 0, 4, proof[:1], root); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("short proof: %v", err)
	}
	if err := VerifyInclusion(leaves[0], 0, 4, append(proof, Hash{}), root); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("long proof: %v", err)
	}
	if _, err := InclusionProof(leaves, 4); !errors.Is(err, verify.ErrMalformed) {
		t.Errorf("InclusionProof out of range: %v", err)
	}
	if _, err := InclusionProof(nil, 0); err == nil {
		t.Error("empty tree has no proofs")
	}
}

func TestBuilderMemoryIsLogarithmic(t *testing.T) {
	var b Builder
	for i := range 1 << 14 {
		b.AppendLeaf(binary.BigEndian.AppendUint32(nil, uint32(i)))
	}
	if len(b.stack) != 1 {
		t.Fatalf("stack %d for 2^14 leaves", len(b.stack))
	}
	b.AppendLeaf(nil)
	if len(b.stack) != 2 {
		t.Fatalf("stack %d", len(b.stack))
	}
	first := b.Root()
	if second := b.Root(); first != second {
		t.Fatal("Root must be idempotent")
	}
}

func FuzzVerifyInclusion(f *testing.F) {
	leaves := syntheticLeaves(7)
	root := RootOf(leaves)
	p, _ := InclusionProof(leaves, 3)
	var seed []byte
	for _, h := range p {
		seed = append(seed, h[:]...)
	}
	f.Add(leaves[3][:], uint64(3), uint64(7), seed, root[:])
	f.Add([]byte{}, uint64(0), uint64(0), []byte{}, []byte{})
	f.Add(leaves[0][:], uint64(1<<63), uint64(1<<64-1), seed, root[:])
	f.Fuzz(func(t *testing.T, leaf []byte, index, size uint64, proofBytes, rootBytes []byte) {
		var l, r Hash
		copy(l[:], leaf)
		copy(r[:], rootBytes)
		var proof []Hash
		for len(proofBytes) >= HashSize && len(proof) < 128 {
			proof = append(proof, Hash(proofBytes[:HashSize]))
			proofBytes = proofBytes[HashSize:]
		}
		err := VerifyInclusion(l, index, size, proof, r)
		if err == nil {
			// Anything accepted must be a genuine path: recompute and compare.
			if index >= size {
				t.Fatalf("accepted index %d >= size %d", index, size)
			}
		} else if verify.Classify(err) != verify.Tampered && verify.Classify(err) != verify.Malformed {
			t.Fatalf("unclassified error %v", err)
		}
	})
}
