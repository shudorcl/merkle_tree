package downloader

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/shudorcl/merkle_tree/merkle"
	"github.com/shudorcl/merkle_tree/server"
)

// GetFilelist 获取文件夹列表和公钥
func GetFilelist(url string) server.FolderListResponse {
	resp, err := http.Get(url + "/getfilelist")
	if err != nil {
		panic(err)
	}
	var res server.FolderListResponse
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		resp.Body.Close()
		panic(err)
	}
	resp.Body.Close()
	return res
}

// GetMerkleList 获取文件夹下的文件列表和对应的Merkle树根
func GetMerkleList(url string, folder string) server.MerkleResponse {
	resp, err := http.Get(url + "/getfile?file=" + folder)
	if err != nil {
		panic(err)
	}
	var res server.MerkleResponse
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		resp.Body.Close()
		panic(err)
	}
	resp.Body.Close()
	return res
}

// DownloadFile 下载指定URL的文件到指定路径
func DownloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func VerifyMerkleSign(pubilcKey rsa.PublicKey, merklelist server.MerkleResponse) bool {
	err := rsa.VerifyPSS(&pubilcKey, crypto.SHA256, merklelist.MerkleRoot, merklelist.MerkleSign, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false
	}
	return true
}

func CountMerkle(pathList []string) ([]byte, error) {
	verifyList := []merkle.Substance{}
	for _, path := range pathList {
		verifyList = append(verifyList, merkle.FileContent{FileName: path})
	}
	verifyTree, err := merkle.NewTree(verifyList)
	return verifyTree.RootHash(), err
}

func TestModeBreak(path string) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		fmt.Println("Read file failed")
	}
	defer file.Close()
	if _, err = file.WriteString("\n"); err != nil {
		panic(err)
	}
	fmt.Println("file changed")
}
