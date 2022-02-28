# Merkle Tree

如诸君所见，是二零二一学年冬季学期计算机安全与保密技术课程期末大作业——Merkle树

吼吼吼，其实全称叫——基于Merkle哈希树的网络文件完整性校验

## 系统功能

对于下载网络文件这一场景，构建了一个可以验证一组文件完整性的Merkle树签名校验体系，包含文件服务器和对应的下载器

## 系统设计

### 系统的组成结构

系统的组成结构分为四部分：主函数，下载器，文件服务器和最为核心的Merkle树构造部分

### 数据结构

#### Substance接口

定义了Substance接口，其中包含计算哈希函数，用于规约各种信息到结点之间的转化

```go
type Substance interface {
	CalculateHash() ([]byte, error)
}
```

在此基础上建立了FileContent结构体，实现文件路径到FileContent的转化

```go
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
```

#### Merkle树和结点

定义了Node结构体作为树的节点

```go
type Node struct {
	Tree   *Merkle
	Parent *Node
	Left   *Node
	Right  *Node
	Hash   []byte
	Sub    Substance
}
```

对于树，则单独定义了Merkle结构体

```go
type Merkle struct {
	Root     *Node
	rootHash []byte
	Leafs    []*Node
	hashFunc func() hash.Hash
}
```

### Merkle树构造算法

定义了三个函数
NewTree函数为公开函数，用于构造新哈希树

```go
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
```

buildWithSubstance函数用于将满足Substance接口的结构体转化为第一层结点，buildMiddleLayers函数则递归逐层建立Merkle树

```go
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
```

#### 服务器发送报文

定义了FolderListResponse和MerkleResponse结构体，作为文件夹列表请求和文件夹内容请求报文的回复报文

```go
type MerkleResponse struct {
	Code       string
	FileList   []string
	MerkleRoot []byte
	MerkleSign []byte
}

type FolderListResponse struct {
	Code       string
	FolderList []string
	PublicKey  rsa.PublicKey
}
```

### 系统的工作流程

首先，文件服务器在初始化时会确定私钥和公钥，并由参数确定文件服务的目录

下载器在下载前会对`/getfilelist`发送GET请求，获得文件夹目录和公钥，之后由用户选择需要下载的文件夹

用户选择后，下载器再对`/getfile?file={文件夹}`发送GET请求，此时文件服务器会即时计算这组文件的Merkle树根并签名，返回给下载器Merkle树根的签名和文件列表

这之后，下载器根据返回的文件列表下载文件，最后在本地计算这组文件的Merkle树根，并对数字签名进行验证，若验证成功，则再比较Merkle树根，若Merkle树根依然一致，则说明下载的文件与服务器的一致，校验完成

## 闲谈

这门课好吃又好玩，强推！
