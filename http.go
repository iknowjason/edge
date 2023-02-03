package main

import (
	"io"
	"net/http"
	"os"
	"fmt"
)

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

func main() {

    // Start of AWS - download fresh prefix list
    fileUrlAws := "https://ip-ranges.amazonaws.com/ip-ranges.json"
    err2 := DownloadFile("ip-ranges.json", fileUrlAws)
    if err2 != nil {
        panic(err2)
        fmt.Println("Error downloading aws IP ranges - using default")
    } else {
        fmt.Println("Downloaded: ", fileUrlAws)
    }

    // Start of Google Cloud
    fileUrlG := "https://www.gstatic.com/ipranges/goog.json"
    err3 := DownloadFile("goog.json", fileUrlG)
    if err3 != nil {
            panic(err3)
    } else {
        fmt.Println("Downloaded: ", fileUrlG)
    }

    // Start of Azure
    // Azure currently has a dynamic URL that changes
    // hardcode the existing and update as necessary, until a better solution is found
    fileUrlAzure := "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230130.json"
    err4 := DownloadFile("azure.json", fileUrlAzure)

    if err4 != nil {
            panic(err4)
    } else {
        fmt.Println("Downloaded: ", fileUrlAzure)
    }

}

