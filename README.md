# merkletree

An implementation of a merkle tree based on the specification provided for [Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1)

# Usage

```go
package main

import (
	"fmt"

	"github.com/arriqaaq/merkletree"
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


func main() {
	tree := merkletree.NewTree()

	// Insert
	D := makeleaves()
	tree := NewTree(D)

	// Root Hash
	hash:=tree.Hash()

	// Path
	// The audit path for d0 is [b, h, l].
	path := tree.Path(0)

	// Proof
	// The consistency proof between hash0 and hash is PROOF(3, D[7]) = [c,
	// d, g, l].  c, g are used to verify hash0, and d, l are additionally
	// used to show hash is consistent with hash0.
	proof := tree.Proof(3)
}
```

# Reference
- [RFC#6962](https://datatracker.ietf.org/doc/html/rfc6962#section-2.1)
- [Codenotary](https://github.com/codenotary/merkletree)
