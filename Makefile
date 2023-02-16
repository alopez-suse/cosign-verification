pb:
	protoc --go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative \
	api/api.proto

server:
	go run .

client_image_signatures:
	go run ./cli-client --reqType=imageSignatures --imageRef=$(imageRef) 

client_image_signed:
	go run ./cli-client --reqType=imageSigned --imageRef=$(imageRef) --keyPath=$(keyPath) --sigsPath=$(sigsPath)

build:
	env GOARCH=amd64 GOOS=linux go build .
