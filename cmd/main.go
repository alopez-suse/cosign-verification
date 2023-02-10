package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	grpcapi "github.com/alopez-suse/cosign-verification/grpcapi"
)

var (
	addr           = flag.String("addr", "localhost:50051", "the address to connect to")
	imageReference = flag.String("ref", "", "the reference for an image by digest")
	keyPath        = flag.String("key", "", "a path to a public key file to verify against")
)

func main() {
	flag.Parse()

	key := keyFromPath(*keyPath)

	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := grpcapi.NewSignatureVerificationClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.VerifySignatures(ctx, &grpcapi.VerifySignaturesRequest{ImageReference: *imageReference, PublicKey: key})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}

	if r.GetSigned() {
		log.Printf("verified")
	} else {
		log.Printf("not verified")
	}
}

func keyFromPath(path string) string {
	publicKey, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(publicKey)
}
