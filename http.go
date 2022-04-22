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
    fileUrlA := "https://ip-ranges.amazonaws.com/ip-ranges.json"
    err2 := DownloadFile("ip-ranges.json", fileUrlA)
    if err2 != nil {
        panic(err2)
        fmt.Println("Error downloading aws IP ranges - using default")
    } else {
        fmt.Println("Downloaded: ", fileUrlA)
    }


    // Start of Google Cloud
    fileUrlG := "https://www.gstatic.com/ipranges/goog.json"
    err3 := DownloadFile("goog.json", fileUrlG)
    if err3 != nil {
            panic(err3)
    } else {
        fmt.Println("Downloaded: ", fileUrlG)
    }

}
