package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/alopez-suse/cosign-verification/api"
)

type Signatures struct {
	Payload         string `json:"Payload"`
	Base64Signature string `json:"Base64Signature"`
}

var (
	requestType    = flag.String("reqType", "", "the type of request to make to the grpc server")
	addr           = flag.String("addr", "localhost:50051", "the address to connect to")
	imageReference = flag.String("imageRef", "", "the reference for an image by digest")
	keyPath        = flag.String("keyPath", "", "a path to a public key file to verify against")
	sigPath        = flag.String("sigsPath", "", "path to a file containing the signature array returned by signatures for digest request")
)

func main() {
	flag.Parse()
	switch *requestType {
	case "imageSignatures":
		ImageSignatures()
	case "imageSigned":
		ImageSigned()
	}
}

func ImageSignatures() {
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := api.NewSignatureVerificationClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	r, err := c.ImageSignatures(ctx, &api.ImageSignaturesRequest{ImageReference: *imageReference})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	signatures := r.GetSignatures()
	if len(signatures) > 0 {
		bytes, err := json.Marshal(signatures)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(bytes))
	}
}

func ImageSigned() {
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	c := api.NewSignatureVerificationClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.ImageSigned(ctx, &api.ImageSignedRequest{
		ImageReference: *imageReference,
		PublicKey:      keyFromPath(*keyPath),
		Signatures:     sigsFromPath(*sigPath),
	})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	if r.GetImageSigned() {
		log.Println("validated")
	} else {
		log.Println("not validated")
	}
}

func keyFromPath(path string) string {
	publicKey, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(publicKey)
}

func sigsFromPath(path string) []*api.Signature {
	sigs, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	grpcSigs := []*api.Signature{}
	err = json.Unmarshal(sigs, &grpcSigs)
	if err != nil {
		panic(err)
	}
	return grpcSigs
}
