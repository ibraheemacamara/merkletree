package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

type MerkleTreee struct {
	RootNode *Node
	Leaves   []*Node
}
type Node struct {
	Parent *Node
	Right  *Node
	Left   *Node
	Hash   []byte
}

func NewMerkleTree(hashes [][]byte) (*MerkleTreee, error) {
	if len(hashes) < 1 {
		return &MerkleTreee{}, fmt.Errorf("failed to create merkle tree, not enough elements")
	}

	tree := &MerkleTreee{
		Leaves: make([]*Node, 0, len(hashes)),
	}
	//build tree's nodes
	for _, hash := range hashes {
		tree.Leaves = append(tree.Leaves, &Node{Hash: hash})
	}

	tree.RootNode = tree.buildRootNode()

	return tree, nil
}

func (t *MerkleTreee) buildRootNode() *Node {
	//t.leaves: [T1, T2, T3, T4, T5, T6, T7, T8, T9, T10]
	if len(t.Leaves) == 1 {
		return t.Leaves[0]
	}

	nodes := t.Leaves
	for len(nodes) > 1 {
		var parents []*Node
		//for each branch, if number of leaves is odd, we duplicate the leaf
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		//pairing nodes
		for i := 0; i < len(nodes); i += 2 {
			node := &Node{
				Left:  nodes[i],
				Right: nodes[i+1],
				Hash:  hash(nodes[i].Hash, nodes[i+1].Hash),
			}
			parents = append(parents, node)
			nodes[i].Parent = node
			nodes[i+1].Parent = node
		}
		nodes = parents
	}

	return nodes[0]
}

func (t *MerkleTreee) GetProof(hash []byte) ([][]byte, []int, error) {
	var path [][]byte
	var indexes []int

	for _, currentNode := range t.Leaves {
		if bytes.Equal(currentNode.Hash, hash) {
			parent := currentNode.Parent
			for currentNode.Parent != nil {
				if bytes.Equal(currentNode.Hash, parent.Left.Hash) {
					path = append(path, parent.Right.Hash)
					indexes = append(indexes, 1)
				} else {
					path = append(path, parent.Left.Hash)
					indexes = append(indexes, 0)
				}
				currentNode = parent
				parent = currentNode.Parent
			}
			return path, indexes, nil
		}
	}

	return path, indexes, fmt.Errorf("not found corresponding data in the tree")
}

func VerifyProof(rootHash []byte, value []byte, proofs [][]byte, indexes []int) bool {
	previousHash := value
	for i := 0; i < len(proofs); i++ {
		if indexes[i] == 0 {
			//its left
			previousHash = hash(proofs[i], previousHash)
		} else {
			//its rigth
			previousHash = hash(previousHash, proofs[i])
		}
	}

	return bytes.Equal(rootHash, previousHash)
}

func hash(data ...[]byte) []byte {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	return hasher.Sum(nil)
}
