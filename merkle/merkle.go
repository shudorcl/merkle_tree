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
	Equals(other Substance) (bool, error)
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

func (t FileContent) Equals(other Substance) (bool, error) {
	return t.FileName == other.(FileContent).FileName, nil
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

func NewTree(cs []Substance) (*Merkle, error) {
	t := &Merkle{
		hashFunc: sha256.New,
	}
	root, leafs, err := buildWithSubstance(cs, t)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.rootHash = root.Hash
	return t, nil
}

func buildWithSubstance(subs []Substance, t *Merkle) (*Node, []*Node, error) {
	if len(subs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for _, c := range subs {
		calculateHash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}
		leafs = append(leafs, &Node{
			Hash: calculateHash,
			Sub:  c,
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
	root, err := buildIntermediate(leafs, t)
	if err != nil {
		return nil, nil, err
	}
	return root, leafs, nil
}

func buildIntermediate(nl []*Node, t *Merkle) (*Node, error) {
	var nodes []*Node
	for i := 0; i < len(nl); i += 2 {
		h := t.hashFunc()
		var left, right = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := append(nl[left].Hash, nl[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:  nl[left],
			Right: nl[right],
			Hash:  h.Sum(nil),
			Tree:  t,
		}
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes, t)
}

func (m *Merkle) RootHash() []byte {
	return m.rootHash
}
