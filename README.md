# ed
Ed is a tool used to identify accessible UNIX Domain Sockets

# What does it do?
Ed is a binary to help you find accessible UNIX domain sockets on a container or host. This is useful for hunting Docker.sock when it has been mounted to a non-default location and or not mounted with the defualt name i.e  "/var/run/Docker.sock".

# Why ed?
Finding exposed UNIX domain sockets, especially Docker.sock, is very useful ;) Ed can be useful in a DevOps process to ensure that Containers do not have any unnecessarily exposed sockets.

# Usage
Ed can be used to look for plain 'ol UNIX domain sockets, UNIX domain sockets that respond to HTTP requests or UNIX domain sockets that behave like Docker.sock. Ed by default searches from the CWD. To use Ed, get the binary on the host and use the following options:

 ```
  ./ed -h
[+] Hunt 'dem Socks
Usage of ./ed:
  -docker
        Hunt for docker.sock
  -http
        Hunt for Available UNIX Domain Sockets with HTTP
  -path string
        Path to Start Scanning for UNIX Domain Sockets (default ".")
  -socket
        Hunt for Available UNIX Domain Sockets (default true)
  -verbose
        Verbose output

```
 Example: Look for exposed Docker.sock
 
 ```
 root@2ae7f389d44c:/app# ./ed -path=/    
[+] Hunt 'dem Socks
[+] Hunting Down UNIX Domain Sockets from: /
[*] Valid Socket: /run/docker.sock
 
 ```
 
 # License
 Ed is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0).
