package verification

import (
	"context"
	"crypto"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	coSig "github.com/sigstore/cosign/pkg/signature"
)

func DigestSignedByKey(digest name.Digest, signatures []oci.Signature, publicKeyToken string) bool {
	return len(DigestSignaturesFromKey(digest, signatures, publicKeyToken)) > 0
}

func DigestSignaturesFromKey(digest name.Digest, signatures []oci.Signature, publicKeyToken string) []oci.Signature {
	ctx := context.Background()

	digestHash, err := v1.NewHash(digest.Identifier())
	if err != nil {
		panic(err)
	}

	verifier, err := coSig.LoadPublicKeyRaw([]byte(publicKeyToken), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	checkOpts := cosign.CheckOpts{
		SigVerifier: verifier,
	}

	validSigatures := []oci.Signature{}
	for _, signature := range signatures {
		verified, err := imageSignatureIsVerified(ctx, signature, digestHash, &checkOpts)
		if err != nil {
			panic(err)
		}

		if verified {
			validSigatures = append(validSigatures, signature)
		}
	}

	return validSigatures
}

func GetSignaturesForDigest(digest name.Digest) []oci.Signature {
	st, err := ociremote.SignatureTag(digest)
	if err != nil {
		panic(err)
	}

	ociSignatures, err := ociremote.Signatures(st)
	if err != nil {
		panic(err)
	}

	signatures, err := ociSignatures.Get()
	if err != nil {
		panic(err)
	}

	return signatures
}

func imageSignatureIsVerified(ctx context.Context, signature oci.Signature, digestHash v1.Hash, checkOpts *cosign.CheckOpts) (bool, error) {
	_, err := cosign.VerifyImageSignature(ctx, signature, digestHash, checkOpts)
	if err != nil {
		// this is the "error" that is returned when the signature does not match, it is
		// expected behavior when checking possibly invalid signatures, so we want to ignore
		// it and only throw an error that would cause potential errors
		if err.Error() != "invalid signature when validating ASN.1 encoded signature" {
			return false, err
		}

		return false, nil
	}

	// when the function `cosign.VerifyImageSignature` function does not throw an error
	// we have found our valid signature
	return true, nil
}
