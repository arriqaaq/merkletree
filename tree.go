// Implementation as per https://tools.ietf.org/html/rfc6962#section-2.1

package merkletree

import (
	"crypto/sha256"
)

const (
	LeafPrefix = byte(0)
	NodePrefix = byte(1)
)

type (
	// Path is a list of nodes required for proving inclusion or consistency.
	Path [][sha256.Size]byte

	// Tree implements a general purpose Merkle tree.
	Tree struct {
		entries [][]byte
	}
)

func NewTree(entries [][]byte) *Tree {
	return &Tree{
		entries: entries,
	}
}

func (t *Tree) Hash() [sha256.Size]byte {
	return t.hash(t.entries)
}

/*
   Logs use a binary Merkle Hash Tree for efficient auditing.  The
   hashing algorithm is SHA-256 [FIPS.180-4] (note that this is fixed
   for this experiment, but it is anticipated that each log would be
   able to specify a hash algorithm).  The input to the Merkle Tree Hash
   is a list of data entries; these entries will be hashed to form the
   leaves of the Merkle Hash Tree.  The output is a single 32-byte
   Merkle Tree Hash.  Given an ordered list of n inputs, D[n] = {d(0),
   d(1), ..., d(n-1)}, the Merkle Tree Hash (MTH) is thus defined as
   follows:
*/
func (t *Tree) hash(D [][]byte) [sha256.Size]byte {
	n := uint64(len(D))
	/*
		The hash of an empty list is the hash of an empty string:
		MTH({}) = SHA-256().
	*/
	if n == 0 {
		return sha256.Sum256(nil)
	}
	/*
		The hash of a list with one entry (also known as a leaf hash) is:
		MTH({d(0)}) = SHA-256(0x00 || d(0)).
	*/
	if n == 1 {
		c := []byte{LeafPrefix}
		c = append(c, D[0]...)
		return sha256.Sum256(c)
	}

	/*
		For n > 1, let k be the largest power of two smaller than n (i.e.,
		k < n <= 2k).  The Merkle Tree Hash of an n-element list D[n] is then
		defined recursively as

		MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),

		where || is concatenation and D[k1:k2] denotes the list {d(k1),
		d(k1+1),..., d(k2-1)} of length (k2 - k1).  (Note that the hash
		calculations for leaves and nodes differ.  This domain separation is
		required to give second preimage resistance.)

		Note that we do not require the length of the input list to be a
		power of two.  The resulting Merkle Tree may thus not be balanced;
		however, its shape is uniquely determined by the number of leaves.
		(Note: This Merkle Tree is essentially the same as the history tree
		[CrosbyWallach] proposal, except our definition handles non-full
		trees differently.)
	*/
	k := largestPowerOf2LessThan(n)

	c := []byte{NodePrefix}
	x := t.hash(D[0:k])
	c = append(c, x[:]...)
	x = t.hash(D[k:n])
	c = append(c, x[:]...)
	return sha256.Sum256(c)
}

func largestPowerOf2LessThan(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	t := uint64(0)
	for i := 0; i < 64; i++ {
		c := uint64(1 << i)
		if c > n-1 {
			return t
		}
		t = c
	}
	return 0
}

/*
   A Merkle audit path for a leaf in a Merkle Hash Tree is the shortest
   list of additional nodes in the Merkle Tree required to compute the
   Merkle Tree Hash for that tree.  Each node in the tree is either a
   leaf node or is computed from the two nodes immediately below it
   (i.e., towards the leaves).  At each step up the tree (towards the
   root), a node from the audit path is combined with the node computed
   so far.  In other words, the audit path consists of the list of
   missing nodes required to compute the nodes leading from a leaf to
   the root of the tree.  If the root computed from the audit path
   matches the true root, then the audit path is proof that the leaf
   exists in the tree.
*/
func (t *Tree) Path(m uint64) (path Path) {
	return t.path(m, t.entries)
}

func (t *Tree) path(m uint64, D [][]byte) Path {
	/*
		The path for the single leaf in a tree with a one-element input list
		D[1] = {d(0)} is empty:

		PATH(0, {d(0)}) = {}
	*/
	n := uint64(len(D))
	p := make(Path, 0)
	if n == 1 && m == 0 {
		return p
	}

	/*
		For n > 1, let k be the largest power of two smaller than n.  The
		path for the (m+1)th element d(m) in a list of n > m elements is then
		defined recursively as

		PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) for m < k; and

		PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]) for m >= k,

		where : is concatenation of lists and D[k1:k2] denotes the length
		(k2 - k1) list {d(k1), d(k1+1),..., d(k2-1)} as before.
	*/
	k := largestPowerOf2LessThan(n)
	if m < k {
		p = append(p, t.path(m, D[0:k])...)
		p = append(p, t.hash(D[k:n]))
	} else {
		p = append(p, t.path(m-k, D[k:n])...)
		p = append(p, t.hash(D[0:k]))
	}
	return p
}

/*
   Merkle consistency proofs prove the append-only property of the tree.
   A Merkle consistency proof for a Merkle Tree Hash MTH(D[n]) and a
   previously advertised hash MTH(D[0:m]) of the first m leaves, m <= n,
   is the list of nodes in the Merkle Tree required to verify that the
   first m inputs D[0:m] are equal in both trees.  Thus, a consistency
   proof must contain a set of intermediate nodes (i.e., commitments to
   inputs) sufficient to verify MTH(D[n]), such that (a subset of) the
   same nodes can be used to verify MTH(D[0:m]).  We define an algorithm
   that outputs the (unique) minimal consistency proof.
*/
func (t *Tree) Proof(m uint64) Path {
	return t.proof(m, t.entries)
}

func (t *Tree) proof(m uint64, D [][]byte) Path {
	/*
		Given an ordered list of n inputs to the tree, D[n] = {d(0), ...,
		d(n-1)}, the Merkle consistency proof PROOF(m, D[n]) for a previous
		Merkle Tree Hash MTH(D[0:m]), 0 < m < n, is defined as:

		PROOF(m, D[n]) = SUBPROOF(m, D[n], true)

		The subproof for m = n is empty if m is the value for which PROOF was
		originally requested (meaning that the subtree Merkle Tree Hash
		MTH(D[0:m]) is known):

		SUBPROOF(m, D[m], true) = {}
	*/
	n := uint64(len(D))
	if 0 < m && m < n {
		return t.subProof(m, D, true)
	}
	return nil
}

func (t *Tree) subProof(m uint64, D [][]byte, b bool) Path {
	/*
	   The subproof for m = n is the Merkle Tree Hash committing inputs
	   D[0:m]; otherwise:

	   SUBPROOF(m, D[m], false) = {MTH(D[m])}

	   For m < n, let k be the largest power of two smaller than n.  The
	   subproof is then defined recursively.

	   If m <= k, the right subtree entries D[k:n] only exist in the current
	   tree.  We prove that the left subtree entries D[0:k] are consistent
	   and add a commitment to D[k:n]:

	   SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])

	   If m > k, the left subtree entries D[0:k] are identical in both
	   trees.  We prove that the right subtree entries D[k:n] are consistent
	   and add a commitment to D[0:k].

	   SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])

	   Here, : is a concatenation of lists, and D[k1:k2] denotes the length
	   (k2 - k1) list {d(k1), d(k1+1),..., d(k2-1)} as before.

	   The number of nodes in the resulting proof is bounded above by
	   ceil(log2(n)) + 1.

	*/

	path := make(Path, 0)
	n := uint64(len(D))

	if m == n {
		if !b {
			path = append(path, t.hash(D))
		}
		return path
	}

	if m < n {
		k := largestPowerOf2LessThan(n)

		if m <= k {
			path = append(path, t.subProof(m, D[0:k], b)...)
			path = append(path, t.hash(D[k:n]))
		} else {
			path = append(path, t.subProof(m-k, D[k:n], false)...)
			path = append(path, t.hash(D[0:k]))
		}
	}
	return path
}
