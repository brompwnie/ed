FROM golang:latest
RUN mkdir /app 
add . /app
WORKDIR /app 
RUN go get github.com/tv42/httpunix
RUN go build -o main . 
CMD ["/app/main"]
RUN ./main -socket=true