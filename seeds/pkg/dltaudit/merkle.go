package dltaudit

import (
	"crypto/sha256"
	"errors"
)

// BuildMerkleTree constructs a Merkle tree from leaf hashes and returns the root and full tree.
// The tree is stored as a flat slice: tree[0] is the root, leaves start at index (len(tree)/2).
// Each level is stored left-to-right. For an odd number of nodes, the last node is duplicated.
func BuildMerkleTree(hashes [][]byte) (root []byte, tree [][]byte) {
	if len(hashes) == 0 {
		return nil, nil
	}

	// Ensure leaf count is a power of two by duplicating the last leaf
	leaves := make([][]byte, len(hashes))
	copy(leaves, hashes)
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build tree bottom-up; store each level
	levels := [][][]byte{leaves}
	current := leaves

	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			combined := append(current[i], current[i+1]...)
			h := sha256.Sum256(combined)
			next = append(next, h[:])
		}
		levels = append(levels, next)
		current = next
	}

	// Flatten tree: root first, then each level top-to-bottom
	// Store in breadth-first order for easy proof generation
	for i := len(levels) - 1; i >= 0; i-- {
		tree = append(tree, levels[i]...)
	}

	root = current[0]
	return root, tree
}

// GenerateProof generates a Merkle inclusion proof for the leaf at the given index.
// The proof consists of sibling hashes needed to recompute the root from the leaf.
func GenerateProof(tree [][]byte, index int) [][]byte {
	if len(tree) == 0 {
		return nil
	}

	// Reconstruct tree structure from flat slice to determine levels
	// Total nodes in a complete binary tree with N leaves = 2N - 1
	totalNodes := len(tree)
	// Number of leaves is (totalNodes + 1) / 2
	numLeaves := (totalNodes + 1) / 2

	if index < 0 || index >= numLeaves {
		return nil
	}

	// Leaves are the last numLeaves entries in the breadth-first tree
	var proof [][]byte
	levelStart := totalNodes - numLeaves
	pos := index

	for levelStart > 0 {
		// Sibling index
		var siblingIdx int
		if pos%2 == 0 {
			siblingIdx = levelStart + pos + 1
		} else {
			siblingIdx = levelStart + pos - 1
		}

		if siblingIdx < totalNodes {
			proof = append(proof, tree[siblingIdx])
		}

		// Move up one level
		pos = pos / 2
		// Previous level start
		levelSize := numLeaves
		accum := 0
		for accum+levelSize <= levelStart {
			accum += levelSize
			levelSize /= 2
		}
		levelStart = accum - levelSize
		if levelStart < 0 {
			levelStart = 0
		}
	}

	return proof
}

// VerifyProof verifies a Merkle inclusion proof.
// Given a root, leaf hash, proof path, and the leaf index, it recomputes the root
// and checks it matches.
func VerifyProof(root, leaf []byte, proof [][]byte, index int) bool {
	if len(root) == 0 || len(leaf) == 0 {
		return false
	}

	current := make([]byte, len(leaf))
	copy(current, leaf)

	pos := index
	for _, sibling := range proof {
		var combined []byte
		if pos%2 == 0 {
			combined = append(current, sibling...)
		} else {
			combined = append(sibling, current...)
		}
		h := sha256.Sum256(combined)
		current = h[:]
		pos /= 2
	}

	if len(current) != len(root) {
		return false
	}
	for i := range current {
		if current[i] != root[i] {
			return false
		}
	}
	return true
}

// HashEvent computes the SHA-256 hash of an audit event's content.
func HashEvent(eventID string, data []byte) []byte {
	h := sha256.New()
	h.Write([]byte(eventID))
	h.Write(data)
	return h.Sum(nil)
}

// BuildMerkleRoot is a convenience function that returns only the root hash.
func BuildMerkleRoot(hashes [][]byte) ([]byte, error) {
	if len(hashes) == 0 {
		return nil, errors.New("dltaudit/merkle: no hashes provided")
	}
	root, _ := BuildMerkleTree(hashes)
	return root, nil
}
