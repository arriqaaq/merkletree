// Implementation as per https://tools.ietf.org/html/rfc6962#section-2.1

package merkletree

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
 The binary Merkle Tree with 7 leaves:

               hash
              /    \
             /      \
            /        \
           /          \
          /            \
         k              l
        / \            / \
       /   \          /   \
      /     \        /     \
     g       h      i      j
    / \     / \    / \     |
    a b     c d    e f     d6
    | |     | |    | |
   d0 d1   d2 d3  d4 d5
*/

func makeleaves() (D [][]byte) {
	for i := 0; i < 7; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
	}
	return
}

func TestAuditPath(t *testing.T) {
	D := makeleaves()
	tree := NewTree(D)
	// The audit path for d0 is [b, h, l].
	path := tree.Path(0)
	assert.Len(t, path, 3)
	// The audit path for d3 is [c, g, l].
	path = tree.Path(3)
	assert.Len(t, path, 3)
	// The audit path for d4 is [f, j, k].
	path = tree.Path(4)
	assert.Len(t, path, 3)
	// The audit path for d6 is [i, k].
	path = tree.Path(6)
	assert.Len(t, path, 2)
}

/*

The same tree, built incrementally in four steps:

       hash0          hash1=k
       / \              /  \
      /   \            /    \
     /     \          /      \
     g      c         g       h
    / \     |        / \     / \
    a b     d2       a b     c d
    | |              | |     | |
   d0 d1            d0 d1   d2 d3

             hash2                    hash
             /  \                    /    \
            /    \                  /      \
           /      \                /        \
          /        \              /          \
         /          \            /            \
        k            i          k              l
       / \          / \        / \            / \
      /   \         e f       /   \          /   \
     /     \        | |      /     \        /     \
    g       h      d4 d5    g       h      i      j
   / \     / \             / \     / \    / \     |
   a b     c d             a b     c d    e f     d6
   | |     | |             | |     | |    | |
   d0 d1   d2 d3           d0 d1   d2 d3  d4 d5

*/

func TestConsistencyProof(t *testing.T) {
	D := makeleaves()
	tree := NewTree(D)

	// The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c,
	// d, g, l].  c, g are used to verify hash0, and d, l are additionally
	// used to show hash is consistent with hash0.
	path := tree.Proof(3)
	assert.Len(t, path, 4)

	// The consistency proof between hash1 and hash is PROOF(4, D[7]) = [l].
	// hash can be verified using hash1=k and l.
	path = tree.Proof(4)
	assert.Len(t, path, 1)

	// The consistency proof between hash2 and hash is PROOF(6, D[7]) = [i,
	// j, k].  k, i are used to verify hash2, and j is additionally used to
	// show hash is consistent with hash2.
	path = tree.Proof(6)
	assert.Len(t, path, 3)
}
