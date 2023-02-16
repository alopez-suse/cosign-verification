package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/alopez-suse/cosign-verification/api"
	verification "github.com/alopez-suse/cosign-verification/verification"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	api.UnimplementedSignatureVerificationServer
}

func (s *server) ImageSignatures(ctx context.Context, in *api.ImageSignaturesRequest) (*api.ImageSignaturesReply, error) {
	var apiSignatures []*api.Signature
	signatures, err := verification.ImageSignatures(in.GetImageReference())
	if err != nil {
		return nil, err
	}
	for _, signature := range signatures {
		apiSignatures = append(apiSignatures, &api.Signature{
			Payload:         signature.Payload,
			Base64Signature: signature.Base64Signature,
		})
	}
	return &api.ImageSignaturesReply{Signatures: apiSignatures}, nil
}

func (s *server) ImageSigned(ctx context.Context, in *api.ImageSignedRequest) (*api.ImageSignedReply, error) {
	var signatures []verification.Signature
	for _, apiSignature := range in.GetSignatures() {
		signatures = append(signatures, verification.Signature{
			Payload:         apiSignature.GetPayload(),
			Base64Signature: apiSignature.GetBase64Signature(),
		})
	}
	imageSigned, err := verification.ImageSigned(in.GetImageReference(), signatures, in.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &api.ImageSignedReply{ImageSigned: imageSigned}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	api.RegisterSignatureVerificationServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
