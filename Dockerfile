FROM golang:latest
RUN mkdir /app 
ADD . /app
WORKDIR /app 
RUN go get github.com/tv42/httpunix
RUN go get github.com/kr/pty
RUN go get golang.org/x/crypto/ssh/terminal
RUN go build -o main . 
RUN ./main -socket=true -path="/"