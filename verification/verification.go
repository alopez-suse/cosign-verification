package verification

import (
	"context"
	"crypto"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/cosign"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/static"
	coSig "github.com/sigstore/cosign/pkg/signature"
)

type Signature struct {
	Payload         string
	Base64Signature string
}

func ImageSignatures(imageReference string) ([]Signature, error) {
	imageReferenceObj, err := name.NewDigest(imageReference)
	if err != nil {
		return nil, fmt.Errorf("could not create digest object from given image reference: %s", err.Error())
	}
	signatureReferenceObj, err := ociremote.SignatureTag(imageReferenceObj)
	if err != nil {
		return nil, fmt.Errorf("could not create signature tag from given image reference: %s", err.Error())
	}
	cosignSignaturesWrapper, err := ociremote.Signatures(signatureReferenceObj)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve signatures: %s", err.Error())
	}
	cosignSignatures, err := cosignSignaturesWrapper.Get()
	if err != nil {
		return nil, fmt.Errorf("could not extract signatures from cosign signature wrapper: %s", err.Error())
	}
	fmt.Println(cosignSignatures)
	signatures := []Signature{}
	for _, cosignSignature := range cosignSignatures {
		payload, err := cosignSignature.Payload()
		if err != nil {
			return nil, fmt.Errorf("could not extract payload from cosign signature: %s", err.Error())
		}
		base64Signature, err := cosignSignature.Base64Signature()
		if err != nil {
			return nil, fmt.Errorf("could not extract base 64 signature from cosign signature: %s", err.Error())
		}
		signature := Signature{
			Payload:         string(payload),
			Base64Signature: base64Signature,
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

func ImageSigned(imageReference string, signatures []Signature, publicKey string) (bool, error) {
	verifiedSignatures, err := verifiedSignatures(imageReference, signatures, publicKey)
	if err != nil {
		return false, fmt.Errorf("could not verify signatures: %s", err.Error())
	}
	return len(verifiedSignatures) > 0, nil
}

func verifiedSignatures(imageReference string, signatures []Signature, publicKey string) ([]Signature, error) {
	imageReferenceObj, err := name.NewDigest(imageReference)
	if err != nil {
		return nil, fmt.Errorf("could not create digest object from given image reference: %s", err.Error())
	}
	imageDigestHash, err := v1.NewHash(imageReferenceObj.Identifier())
	if err != nil {
		return nil, fmt.Errorf("could not create digest hash from image digest object: %s", err.Error())
	}
	cosignVerifier, err := coSig.LoadPublicKeyRaw([]byte(publicKey), crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("could not load pem encoded public key: %s", err.Error())
	}
	checkOpts := cosign.CheckOpts{
		SigVerifier: cosignVerifier,
	}
	ctx := context.Background()
	var verifiedSignatures []Signature
	for _, signature := range signatures {
		signatureIsVerified, err := signatureIsVerified(ctx, signature, imageDigestHash, &checkOpts)
		if err != nil {
			return nil, fmt.Errorf("could not verify signature: %s", err.Error())
		}
		if signatureIsVerified {
			verifiedSignatures = append(verifiedSignatures, signature)
		}
	}
	return verifiedSignatures, nil
}

func signatureIsVerified(ctx context.Context, signature Signature, digestHash v1.Hash, checkOpts *cosign.CheckOpts) (bool, error) {
	cosignSignature, err := static.NewSignature([]byte(signature.Payload), signature.Base64Signature)
	if err != nil {
		return false, fmt.Errorf("could not generate cosign signature from given signature object: %s", err.Error())
	}
	_, err = cosign.VerifyImageSignature(ctx, cosignSignature, digestHash, checkOpts)
	if err != nil {
		// this is the "error" that is returned when the signature does not match, it is
		// expected behavior when checking possibly invalid signatures, so we want to ignore
		// it and only throw an error that would cause potential errors
		if err.Error() != "invalid signature when validating ASN.1 encoded signature" {
			return false, fmt.Errorf("could not verify cosign signature: %s", err.Error())
		}
		return false, nil
	}
	// when the function `cosign.VerifyImageSignature` function does not throw an error
	// we have found our valid signature
	return true, nil
}
