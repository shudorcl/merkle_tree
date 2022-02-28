package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/shudorcl/merkle_tree/merkle"
)

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

var privateKey *rsa.PrivateKey

func init() {
	pKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	privateKey = pKey
}

var workFilelist = []string{}

var workDirectory string = "."

func MerkleHandler(w http.ResponseWriter, r *http.Request) {
	keys, ok := r.URL.Query()["file"]
	var resp MerkleResponse
	findFlag := true
	if ok {
		name := keys[0]
		log.Println("Recieved get ask for file", name)
		for _, file := range workFilelist {
			if file == name {
				findDirectory := workDirectory + "/" + name
				filelist, err := getfilelist(findDirectory, false)
				if err != nil {
					panic(err)
				}
				log.Println("Calculating merkle tree for", name)
				merkleRoot := merkleCalculate(findDirectory)
				signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, merkleRoot, nil)
				if err != nil {
					panic(err)
				}
				resp = MerkleResponse{
					Code:       "1",
					FileList:   filelist,
					MerkleRoot: merkleRoot,
					MerkleSign: signature,
				}
				findFlag = false
				break
			}
		}
	}
	if findFlag {
		resp = MerkleResponse{Code: "0"}
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

func FilelistHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Recieved get ask for filelist. ")
	resp := FolderListResponse{
		Code:       "1",
		FolderList: workFilelist,
		PublicKey:  privateKey.PublicKey,
	}
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
}

func getfilelist(directory string, dirflag bool) ([]string, error) {
	var filelist = []string{}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		if dirflag {
			if file.IsDir() {
				filelist = append(filelist, file.Name())
			}
		} else {
			if !file.IsDir() {
				filelist = append(filelist, file.Name())
			}
		}
	}
	return filelist, err
}

func SetDirectory(directory string) {
	workDirectory = directory
	folderlist, err := getfilelist(directory, true)
	if err != nil {
		panic(err)
	}
	workFilelist = folderlist
}

func merkleCalculate(directory string) []byte {
	var merkleList = []merkle.Substance{}
	files, err := ioutil.ReadDir(directory)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if !file.IsDir() {
			merkleList = append(merkleList,
				merkle.FileContent{FileName: directory + "/" + file.Name()})
		}
	}
	t, err := merkle.NewTree(merkleList)
	if err != nil {
		log.Fatal(err)
	}
	return t.RootHash()
}
