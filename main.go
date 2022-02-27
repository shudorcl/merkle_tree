package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/shudorcl/merkle_tree/downloader"
	"github.com/shudorcl/merkle_tree/server"
)

func main() {
	port := flag.String("p", "8100", "port to serve on")
	directory := flag.String("d", "./MerkleFiles", "the directory of static file to host")
	severFlag := flag.Bool("s", false, "run as server(T) or downloader(F)")
	url := flag.String("u", "http://localhost:8100", "URL for downloader mode")
	testMode := flag.Bool("t", false, "run as test mode(T) or not(F)")
	flag.Parse()
	if *severFlag {
		server.SetDirectory(*directory)
		http.HandleFunc("/getfilelist", server.FilelistHandler)
		http.HandleFunc("/getfile", server.MerkleHandler)
		http.Handle("/MerkleFiles/", http.StripPrefix("/MerkleFiles/", http.FileServer(http.Dir(*directory))))
		log.Printf("Serving %s on HTTP port: %s\n", *directory, *port)
		log.Fatal(http.ListenAndServe(":"+*port, nil))
	} else {
		fmt.Println("Getting folderlist...")
		folderResp := downloader.GetFilelist(*url)
		if folderResp.Code == "0" {
			fmt.Println("Getting list wrong")
			os.Exit(0)
		}
		fmt.Println("Publickey:", folderResp.PublicKey)
		fmt.Println("Folderlist:", folderResp.FolderList)
		var selection string
		fmt.Print("What's your selection? ")
		fmt.Scanln(&selection)
		merkleList := downloader.GetMerkleList(*url, selection)
		if merkleList.Code == "0" {
			fmt.Println("Wrong Folder. Please check input.")
		} else {
			fmt.Println("Filelist", merkleList.FileList)
			fmt.Printf("MerkleSign:%X\n", merkleList.MerkleSign)
			fmt.Printf("MerkleRoot:%X\n", merkleList.MerkleRoot)
			downloadDir := "." + "/DownloadFiles/" + selection
			err := os.MkdirAll(downloadDir, os.ModePerm)
			if err != nil {
				panic(err)
			}
			fmt.Println("Start downloading...")
			downloadPathList := []string{}
			for _, filename := range merkleList.FileList {
				downloadUrl := *url + "/MerkleFiles/" + selection + "/" + filename
				downloadPath := downloadDir + "/" + filename
				downloadPathList = append(downloadPathList, downloadPath)
				downloader.DownloadFile(downloadPath, downloadUrl)
			}
			if *testMode {
				fmt.Println("Test mode on. Change the first file!")
				downloader.TestModeBreak(downloadPathList[0])
			}
			fmt.Println("Download Complete. Verfying...")
			if downloader.VerifyMerkleSign(downloadPathList, folderResp.PublicKey, merkleList) {
				fmt.Println("Verify Complete. The files are consistent")
			} else {
				fmt.Println("Verify Fail. The files are NOT consistent!")
			}
		}
	}
}
