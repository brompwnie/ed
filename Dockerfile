FROM golang:latest
RUN mkdir /app 
ADD . /app
WORKDIR /app 
RUN go get github.com/tv42/httpunix
RUN go build -o main . 
RUN ./main -socket=true -path="/"