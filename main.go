package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tv42/httpunix"
)

var verbosePtr, huntSockPtr, huntHttpPtr, huntDockerPtr *bool
var validSocks []string

func main() {
	fmt.Println("[+] Hunt 'dem Socks")

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pathPtr := flag.String("path", ".", "Path to Start Scanning for UNIX Domain Sockets")
	verbosePtr = flag.Bool("verbose", false, "Verbose output")
	huntSockPtr = flag.Bool("socket", true, "Hunt for Available UNIX Domain Sockets")
	huntHttpPtr = flag.Bool("http", false, "Hunt for Available UNIX Domain Sockets with HTTP")
	huntDockerPtr = flag.Bool("docker", false, "Hunt for docker.sock")

	flag.Parse()
	var sockets, httpSockets []string

	if *huntSockPtr {
		fmt.Println("[+] Hunting Down UNIX Domain Sockets from:", *pathPtr)
		sockets, _ = getValidSockets(*pathPtr)
		for _, element := range sockets {
			fmt.Println("[*] Valid Socket: " + element)
		}
	}

	if *huntHttpPtr {
		fmt.Println("[+] Hunting Down HTTP UNIX Domain Sockets from:", *pathPtr)
		if len(sockets) == 0 {
			sockets, _ = getValidSockets(*pathPtr)
		}
		httpSockets = getHTTPEnabledSockets(sockets)
		for _, element := range httpSockets {
			fmt.Println("[*] Valid HTTP Socket: " + element)
		}
	}

	if *huntDockerPtr {
		fmt.Println("[+] Hunting Down DockerD from:", *pathPtr)
		if len(sockets) == 0 {
			sockets, _ = getValidSockets(*pathPtr)
		}
		if len(httpSockets) == 0 {
			httpSockets = getHTTPEnabledSockets(sockets)
		}
		dockerSocks := getDockerEnabledSockets(httpSockets)
		for _, element := range dockerSocks {
			fmt.Println("[*] Valid Docker Socket: " + element)
		}
	}
}

func getDockerEnabledSockets(socks []string) []string {
	fmt.Println("[+] Hunting Docker Socks")
	var dockerSocks []string
	for _, element := range socks {
		resp, err := checkSock(element)
		if err == nil {
			if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
				dockerSocks = append(dockerSocks, element)
				if *verbosePtr {
					fmt.Println("[+] Valid Docker Socket: " + element)
				}
			} else {
				if *verbosePtr {
					fmt.Println("[+] Invalid Docker Socket: " + element)
				}
			}
			defer resp.Body.Close()
		} else {
			if *verbosePtr {
				fmt.Println("[+] Invalid Docker Socket: " + element)
			}
		}
	}
	return dockerSocks
}

func getHTTPEnabledSockets(socks []string) []string {
	var httpSocks []string
	for _, element := range socks {
		resp, err := checkSock(element)
		if err == nil {
			defer resp.Body.Close()
			httpSocks = append(httpSocks, element)
			if *verbosePtr {
				fmt.Println("[+] Valid HTTP Socket: " + element)
			}
		} else {
			if *verbosePtr {
				fmt.Println("[+] Invalid HTTP Socket: " + element)
			}
		}
	}
	return httpSocks
}

func walkpath(path string, info os.FileInfo, err error) error {
	if err != nil {
		if *verbosePtr {
			fmt.Println("[ERROR]: ", err)
		}
	} else {
		switch mode := info.Mode(); {
		case mode&os.ModeSocket != 0:
			if *verbosePtr {
				fmt.Println("[+] Valid Socket: " + path)
			}
			validSocks = append(validSocks, path)
		default:
			if *verbosePtr {
				fmt.Println("[!] Invalid Socket: " + path)
			}
		}
	}
	return nil
}

func getValidSockets(startPath string) ([]string, error) {

	err := filepath.Walk(startPath, walkpath)
	if err != nil {
		if *verbosePtr {
			fmt.Println("[ERROR]: ", err)
		}
		return nil, err
	}
	return validSocks, nil
}

func checkSock(path string) (*http.Response, error) {

	if *verbosePtr {
		fmt.Println("[-] Checking Sock for HTTP: " + path)
	}

	u := &httpunix.Transport{
		DialTimeout:           100 * time.Millisecond,
		RequestTimeout:        1 * time.Second,
		ResponseHeaderTimeout: 1 * time.Second,
	}
	u.RegisterLocation("dockerd", path)
	var client = http.Client{
		Transport: u,
	}
	resp, err := client.Get("http+unix://dockerd/info")

	if resp == nil {
		return nil, err
	}
	return resp, nil
}

func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}
