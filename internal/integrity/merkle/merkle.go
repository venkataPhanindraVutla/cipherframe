// Package merkle implements the Merkle tree of RFC 9162 section 2.1 (the Certificate Transparency
// v2 tree) with SHA-256: a leaf hash is SHA-256(0x00 || data), an interior hash is
// SHA-256(0x01 || left || right), the empty tree hashes to SHA-256 of the empty string, and a tree
// of n > 1 leaves splits at k, the largest power of two smaller than n.
//
// The package is pure: it depends only on the standard library and on the error taxonomy in
// package verify, so a verifier can be built from it without any secret or service.
//
// [Builder] computes a root in O(log n) memory while leaves are streamed in. [InclusionProof]
// produces an audit path for one leaf; [VerifyInclusion] checks it. Verification errors wrap
// verify.ErrMalformed (structurally impossible input) or verify.ErrTampered (the path does not
// lead to the root).
package merkle

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify"
)

// HashSize is the size of every hash in the tree.
const HashSize = sha256.Size

// Hash is a SHA-256 tree hash.
type Hash [HashSize]byte

const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// EmptyRoot returns the root of a tree with no leaves: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// HashLeaf returns the leaf hash of data: SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// HashChildren returns the interior hash SHA-256(0x01 || left || right).
func HashChildren(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// Builder accumulates leaves one at a time and reports the root of the tree so far. It keeps one
// hash per set bit of the leaf count (a compact range), so memory is O(log n). The zero value is
// an empty tree ready to use.
type Builder struct {
	// stack holds the roots of the perfect subtrees covering the leaves so far, largest first.
	// Their sizes are the set bits of n in descending order.
	stack []Hash
	n     uint64
}

// AppendLeaf hashes data as a leaf and appends it.
func (b *Builder) AppendLeaf(data []byte) { b.AppendLeafHash(HashLeaf(data)) }

// AppendLeafHash appends an already computed leaf hash.
func (b *Builder) AppendLeafHash(leaf Hash) {
	h := leaf
	// Merge equal-sized perfect subtrees: one merge per trailing 1 bit of n.
	for i := b.n; i&1 == 1; i >>= 1 {
		h = HashChildren(b.stack[len(b.stack)-1], h)
		b.stack = b.stack[:len(b.stack)-1]
	}
	b.stack = append(b.stack, h)
	b.n++
}

// Size returns the number of leaves appended.
func (b *Builder) Size() uint64 { return b.n }

// Root returns the root hash of the tree of the leaves appended so far. It does not modify the
// builder.
func (b *Builder) Root() Hash {
	if len(b.stack) == 0 {
		return EmptyRoot()
	}
	root := b.stack[len(b.stack)-1]
	for i := len(b.stack) - 2; i >= 0; i-- {
		root = HashChildren(b.stack[i], root)
	}
	return root
}

// RootOf returns the root of the tree whose leaf hashes are given.
func RootOf(leaves []Hash) Hash {
	var b Builder
	for _, l := range leaves {
		b.AppendLeafHash(l)
	}
	return b.Root()
}

// splitPoint returns the largest power of two strictly smaller than n (n >= 2).
func splitPoint(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// InclusionProof returns the audit path (RFC 9162 section 2.1.3.1) proving that leaves[index] is
// in the tree over leaves. Its length is at most ceil(log2(len(leaves))).
func InclusionProof(leaves []Hash, index uint64) ([]Hash, error) {
	n := uint64(len(leaves))
	if index >= n {
		return nil, fmt.Errorf("%w: leaf index %d out of range for tree size %d", verify.ErrMalformed, index, n)
	}
	return path(leaves, index), nil
}

// path is PATH(m, D[n]) of RFC 9162 section 2.1.3.1.
func path(d []Hash, m uint64) []Hash {
	n := uint64(len(d))
	if n <= 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(path(d[:k], m), RootOf(d[k:]))
	}
	return append(path(d[k:], m-k), RootOf(d[:k]))
}

// VerifyInclusion checks that leaf is the leaf at index of the tree of the given size with the
// given root, using the audit path proof (RFC 9162 section 2.1.3.2). It returns nil on success,
// an error wrapping verify.ErrMalformed if index, size or the proof length cannot belong to any
// valid tree, and an error wrapping verify.ErrTampered if the path computes a different root.
//
// The size is not bound by the hashes: a proof only fixes the path's length and orientation, so a
// different size that yields the same path shape verifies against the same root. A verifier must
// take the size from an authenticated source (the signed manifest), never from the prover.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	if size == 0 {
		return fmt.Errorf("%w: tree size is zero", verify.ErrMalformed)
	}
	if index >= size {
		return fmt.Errorf("%w: leaf index %d out of range for tree size %d", verify.ErrMalformed, index, size)
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return fmt.Errorf("%w: proof is too long", verify.ErrMalformed)
		}
		if fn&1 == 1 || fn == sn {
			r = HashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof is too short", verify.ErrMalformed)
	}
	if r != root {
		return fmt.Errorf("%w: inclusion proof does not match the root", verify.ErrTampered)
	}
	return nil
}
