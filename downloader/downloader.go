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

func VerifyMerkleSign(pathList []string, pubilcKey rsa.PublicKey, merklelist server.MerkleResponse) bool {
	verifyList := []merkle.Substance{}
	for _, path := range pathList {
		verifyList = append(verifyList, merkle.FileContent{FileName: path})
	}
	verifyTree, err := merkle.NewTree(verifyList)
	if err != nil {
		fmt.Println("could not construct verifytree: ", err)
		return false
	}
	err = rsa.VerifyPSS(&pubilcKey, crypto.SHA256, verifyTree.RootHash(), merklelist.MerkleSign, nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false
	}
	return true
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
