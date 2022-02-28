package merkle

import (
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"log"
	"os"
)

type Substance interface {
	CalculateHash() ([]byte, error)
}

type FileContent struct {
	FileName string
}

func (t FileContent) CalculateHash() ([]byte, error) {
	file, err := os.Open(t.FileName)
	if err != nil {
		log.Println("Read file failed")
	}
	hashFunc := sha256.New()
	if _, err := io.Copy(hashFunc, file); err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	return hashFunc.Sum(nil), nil
}

type Node struct {
	Tree   *Merkle
	Parent *Node
	Left   *Node
	Right  *Node
	Hash   []byte
	Sub    Substance
}

type Merkle struct {
	Root     *Node
	rootHash []byte
	Leafs    []*Node
	hashFunc func() hash.Hash
}

func NewTree(s []Substance) (*Merkle, error) {
	t := &Merkle{
		hashFunc: sha256.New,
	}
	root, leafs, err := buildWithSubstance(s, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.rootHash = root.Hash
	return t, nil
}

func buildWithSubstance(subList []Substance, t *Merkle) (*Node, []*Node, error) {
	if len(subList) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, s := range subList {
		calculateHash, err := s.CalculateHash()
		if err != nil {
			return nil, nil, err
		}
		leafs = append(leafs, &Node{
			Hash: calculateHash,
			Sub:  s,
			Tree: t,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash: leafs[len(leafs)-1].Hash,
			Sub:  leafs[len(leafs)-1].Sub,
			Tree: t,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildMiddleLayers(leafs, t)
	if err != nil {
		return nil, nil, err
	}
	return root, leafs, nil
}

func buildMiddleLayers(nodeList []*Node, t *Merkle) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nodeList); i += 2 {
		h := t.hashFunc()
		var left, right = i, i + 1
		if i+1 == len(nodeList) {
			right = i
		}
		chash := append(nodeList[left].Hash, nodeList[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nodeList[left],
			Right: nodeList[right],
			Hash:  h.Sum(nil),
			Tree:  t,
		}
		nodes = append(nodes, n)
		nodeList[left].Parent = n
		nodeList[right].Parent = n
		if len(nodeList) == 2 {
			return n, nil
		}
	}
	return buildMiddleLayers(nodes, t)
}

func (m *Merkle) RootHash() []byte {
	return m.rootHash
}
