package merkletree

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type File struct {
	Id   int
	Name string
	Text string
}

func hashFile(file File) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%v", file)))
	return hasher.Sum(nil)
}

func initData() [][]byte {
	file_0 := File{
		Id:   0,
		Name: "file_0",
		Text: "This is the content of file 0",
	}
	file_1 := File{
		Id:   1,
		Name: "file_1",
		Text: "This is the content of file 1",
	}
	file_2 := File{
		Id:   2,
		Name: "file_2",
		Text: "This is the content of file 2",
	}
	file_3 := File{
		Id:   3,
		Name: "file_3",
		Text: "This is the content of file 3",
	}

	data := [][]byte{
		hashFile(file_0),
		hashFile(file_1),
		hashFile(file_2),
		hashFile(file_3),
	}

	return data
}

func TestNewMerkleTree_ShouldThrowError(t *testing.T) {
	data := [][]byte{}
	tree, err := NewMerkleTree(data)
	assert.Error(t, err)
	assert.Empty(t, tree)
}

func TestNewMerkleTree_ShouldCreateTree(t *testing.T) {
	data := initData()
	tree, err := NewMerkleTree(data)
	assert.NoError(t, err)
	//tree root node parent should be nil
	//tree root node left and rigth should not be nil
	//tree hash should not be empty
	assert.Nil(t, tree.RootNode.Parent)
	assert.NotNil(t, tree.RootNode.Left)
	assert.NotNil(t, tree.RootNode.Right)
	assert.NotEmpty(t, tree.RootNode.Hash)
}

func TestGetProof_ShouldFail(t *testing.T) {
	data := initData()
	tree, err := NewMerkleTree(data)
	assert.NoError(t, err)

	myFakeFile := File{}

	proof, err := tree.GetProof(hashFile(myFakeFile))
	assert.Error(t, err)
	assert.Empty(t, proof.Path)
	assert.EqualValues(t, 0, len(proof.Idxs))
}

func TestGetProof_ShouldGetProof(t *testing.T) {
	data := initData()
	tree, err := NewMerkleTree(data)
	assert.NoError(t, err)

	file := File{
		Id:   2,
		Name: "file_2",
		Text: "This is the content of file 2",
	}

	proof, err := tree.GetProof(hashFile(file))
	assert.NoError(t, err)
	assert.NotEmpty(t, proof.Path)

	//verify
	isValid := VerifyProof(tree.RootNode.Hash, hashFile(file), proof.Path, proof.Idxs)
	assert.True(t, isValid)
}
