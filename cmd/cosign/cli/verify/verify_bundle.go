//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
)

type verifyTrustedMaterial struct {
	root.TrustedMaterial
	keyTrustedMaterial root.TrustedMaterial
}

func (v *verifyTrustedMaterial) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	if v.keyTrustedMaterial == nil {
		return nil, fmt.Errorf("no key in trusted material to verify with")
	}
	return v.keyTrustedMaterial.PublicKeyVerifier(hint)
}

func verifyNewBundle(bundle *sgbundle.Bundle, checkOpts *cosign.CheckOpts, artifactRef string) (*verify.VerificationResult, error) {
	if checkOpts.TrustedMaterial == nil {
		return nil, fmt.Errorf("checkOpts must have TrustedMaterial set")
	}

	if len(checkOpts.IdentityPolicies) == 0 {
		return nil, fmt.Errorf("checkOpts IdentityPolicies must have at least 1 item")
	}

	if len(checkOpts.VerifierOptions) == 0 {
		return nil, fmt.Errorf("checkOpts VerfierOption must have at least 1 item")
	}

	payload, err := payloadBytes(artifactRef)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(payload)

	sev, err := verify.NewSignedEntityVerifier(checkOpts.TrustedMaterial, checkOpts.VerifierOptions...)
	if err != nil {
		return nil, err
	}

	return sev.Verify(bundle, verify.NewPolicy(verify.WithArtifact(buf), checkOpts.IdentityPolicies...))
}

func assembleNewBundle(ctx context.Context, sigBytes, signedTimestamp []byte, envelope *dsse.Envelope, artifactRef string, cert *x509.Certificate, ignoreTlog bool, sigVerifier signature.Verifier, pkOpts []signature.PublicKeyOption, rekorClient *client.Rekor) (*sgbundle.Bundle, error) {
	payload, err := payloadBytes(artifactRef)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(payload)
	digest := sha256.Sum256(buf.Bytes())

	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}

	if envelope != nil && len(envelope.Signatures) > 0 {
		sigDecode, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
		if err != nil {
			return nil, err
		}

		sig := &protodsse.Signature{
			Sig: sigDecode,
		}

		payloadDecode, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return nil, err
		}

		pb.Content = &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     payloadDecode,
				PayloadType: envelope.PayloadType,
				Signatures:  []*protodsse.Signature{sig},
			},
		}
	} else {
		pb.Content = &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sigBytes,
			},
		}
	}

	if cert != nil {
		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{
			Certificate: &protocommon.X509Certificate{
				RawBytes: cert.Raw,
			},
		}
	} else if sigVerifier != nil {
		pub, err := sigVerifier.PublicKey(pkOpts...)
		if err != nil {
			return nil, err
		}
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)

		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: base64.StdEncoding.EncodeToString(hashedBytes[:]),
			},
		}
	}

	if len(signedTimestamp) > 0 {
		ts := &protocommon.RFC3161SignedTimestamp{
			SignedTimestamp: signedTimestamp,
		}

		pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{ts},
		}
	}

	if !ignoreTlog {
		var pem []byte
		var err error
		if cert != nil {
			pem, err = cryptoutils.MarshalCertificateToPEM(cert)
			if err != nil {
				return nil, err
			}
		} else if sigVerifier != nil {
			pub, err := sigVerifier.PublicKey(pkOpts...)
			if err != nil {
				return nil, err
			}
			pem, err = cryptoutils.MarshalPublicKeyToPEM(pub)
			if err != nil {
				return nil, err
			}
		}
		var sigB64 string
		var payload []byte
		if envelope != nil {
			payload = sigBytes
		} else {
			sigB64 = base64.StdEncoding.EncodeToString(sigBytes)
			payload = buf.Bytes()
		}

		tlogEntries, err := cosign.FindTlogEntry(ctx, rekorClient, sigB64, payload, pem)
		if err != nil {
			return nil, err
		}
		if len(tlogEntries) == 0 {
			return nil, fmt.Errorf("unable to find tlog entry")
		}
		// Attempt to verify with the earliest integrated entry
		var earliestLogEntry models.LogEntryAnon
		var earliestLogEntryTime *time.Time
		for _, e := range tlogEntries {
			entryTime := time.Unix(*e.IntegratedTime, 0)
			if earliestLogEntryTime == nil || entryTime.Before(*earliestLogEntryTime) {
				earliestLogEntryTime = &entryTime
				earliestLogEntry = e
			}
		}

		tlogEntry, err := tle.GenerateTransparencyLogEntry(earliestLogEntry)
		if err != nil {
			return nil, err
		}

		pb.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{tlogEntry}
	}

	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func makeTrustedMaterial(trustedRootPath string, sigVerifier *signature.Verifier) (root.TrustedMaterial, *root.TrustedRoot, error) {
	var trustedroot *root.TrustedRoot
	var err error

	if trustedRootPath == "" {
		// Assume we're using public good instance; fetch via TUF
		trustedroot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, nil, err
		}
	} else {
		trustedroot, err = root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return nil, nil, err
		}
	}

	trustedmaterial := &verifyTrustedMaterial{TrustedMaterial: trustedroot}

	if sigVerifier != nil {
		newExpiringKey := root.NewExpiringKey(*sigVerifier, time.Time{}, time.Time{})
		trustedmaterial.keyTrustedMaterial = root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
			return newExpiringKey, nil
		})
	}

	return trustedmaterial, trustedroot, nil
}

func makeIdentityPolicy(bundle *sgbundle.Bundle, certVerifyOpts options.CertVerifyOptions, githubWorkflowTrigger, githubWorkflowSHA, githubWorkflowName, githubWorkflowRepository, githubWorkflowRef string) ([]verify.PolicyOption, error) {
	identityPolicies := []verify.PolicyOption{}

	verificationMaterial := bundle.GetVerificationMaterial()

	if verificationMaterial == nil {
		return nil, fmt.Errorf("no verification material in bundle")
	}

	if verificationMaterial.GetPublicKey() != nil {
		identityPolicies = append(identityPolicies, verify.WithKey())
	} else {
		sanMatcher, err := verify.NewSANMatcher(certVerifyOpts.CertIdentity, certVerifyOpts.CertIdentityRegexp)
		if err != nil {
			return nil, err
		}

		issuerMatcher, err := verify.NewIssuerMatcher(certVerifyOpts.CertOidcIssuer, certVerifyOpts.CertOidcIssuerRegexp)
		if err != nil {
			return nil, err
		}

		extensions := certificate.Extensions{
			GithubWorkflowTrigger:    githubWorkflowTrigger,
			GithubWorkflowSHA:        githubWorkflowSHA,
			GithubWorkflowName:       githubWorkflowName,
			GithubWorkflowRepository: githubWorkflowRepository,
			GithubWorkflowRef:        githubWorkflowRef,
		}

		certIdentity, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
		if err != nil {
			return nil, err
		}

		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(certIdentity))
	}

	return identityPolicies, nil
}

func makeVerifierOptions(trustedroot *root.TrustedRoot, ignoreTlog, useSignedTimestamps, ignoreSCT bool) []verify.VerifierOption {
	// Make some educated guesses about verification policy
	verifierConfig := []verify.VerifierOption{}

	if len(trustedroot.RekorLogs()) > 0 && !ignoreTlog {
		verifierConfig = append(verifierConfig, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	}

	if len(trustedroot.TimestampingAuthorities()) > 0 && useSignedTimestamps {
		verifierConfig = append(verifierConfig, verify.WithSignedTimestamps(1))
	}

	if !ignoreSCT {
		verifierConfig = append(verifierConfig, verify.WithSignedCertificateTimestamps(1))
	}

	if ignoreTlog && !useSignedTimestamps {
		verifierConfig = append(verifierConfig, verify.WithoutAnyObserverTimestampsUnsafe())
	}

	return verifierConfig
}
