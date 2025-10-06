//
// Copyright 2021 The Sigstore Authors.
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

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign/privacy"
	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/cosign/pivkey"
	"github.com/sigstore/cosign/v3/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/v3/pkg/signature"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/protobuf/encoding/protojson"

	// Loads OIDC providers
	_ "github.com/sigstore/cosign/v3/pkg/providers/all"
)

func ShouldUploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool) (bool, error) {
	upload := shouldUploadToTlog(ctx, ko, ref, tlogUpload)
	var statementErr error
	if upload {
		privacy.StatementOnce.Do(func() {
			ui.Infof(ctx, privacy.Statement)
			ui.Infof(ctx, privacy.StatementConfirmation)
			if !ko.SkipConfirmation {
				if err := ui.ConfirmContinue(ctx); err != nil {
					statementErr = err
				}
			}
		})
	}
	return upload, statementErr
}

func shouldUploadToTlog(ctx context.Context, ko options.KeyOpts, ref name.Reference, tlogUpload bool) bool {
	// return false if not uploading to the tlog has been requested
	if !tlogUpload {
		return false
	}

	if ko.SkipConfirmation {
		return true
	}

	// We don't need to validate the ref, just return true
	if ref == nil {
		return true
	}

	// Check if the image is public (no auth in Get)
	if _, err := remote.Get(ref, remote.WithContext(ctx)); err != nil {
		ui.Warnf(ctx, "%q appears to be a private repository, please confirm uploading to the transparency log at %q", ref.Context().String(), ko.RekorURL)
		if ui.ConfirmContinue(ctx) != nil {
			ui.Infof(ctx, "not uploading to transparency log")
			return false
		}
	}
	return true
}

func GetAttachedImageRef(ref name.Reference, attachment string, opts ...ociremote.Option) (name.Reference, error) {
	if attachment == "" {
		return ref, nil
	}
	if attachment == "sbom" {
		return ociremote.SBOMTag(ref, opts...)
	}
	return nil, fmt.Errorf("unknown attachment type %s", attachment)
}

// ParseOCIReference parses a string reference to an OCI image into a reference, warning if the reference did not include a digest.
func ParseOCIReference(ctx context.Context, refStr string, opts ...name.Option) (name.Reference, error) {
	ref, err := name.ParseReference(refStr, opts...)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}
	if _, ok := ref.(name.Digest); !ok {
		ui.Warnf(ctx, ui.TagReferenceMessage, refStr)
	}
	return ref, nil
}

// nolint
func SignCmd(ro *options.RootOptions, ko options.KeyOpts, signOpts options.SignOptions, imgs []string) error {
	if options.NOf(ko.KeyRef, ko.Sk) > 1 {
		return &options.KeyParseError{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), ro.Timeout)
	defer cancel()

	regOpts := signOpts.Registry
	opts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}
	for _, inputImg := range imgs {
		ref, err := ParseOCIReference(ctx, inputImg, regOpts.NameOptions()...)
		if err != nil {
			return err
		}
		ref, err = GetAttachedImageRef(ref, signOpts.Attachment, opts...)
		if err != nil {
			return fmt.Errorf("unable to resolve attachment %s for image %s", signOpts.Attachment, inputImg)
		}

		if digest, ok := ref.(name.Digest); ok {
			err = signDigestBundle(ctx, digest, ko, signOpts)
			if err != nil {
				return fmt.Errorf("signing digest: %w", err)
			}
		}
	}

	return nil
}

func signDigestBundle(ctx context.Context, digest name.Digest, ko options.KeyOpts, signOpts options.SignOptions) error {
	digestParts := strings.Split(digest.DigestStr(), ":")
	if len(digestParts) != 2 {
		return fmt.Errorf("unable to parse digest %s", digest.DigestStr())
	}

	subject := intotov1.ResourceDescriptor{
		Digest: map[string]string{digestParts[0]: digestParts[1]},
	}

	statement := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{&subject},
		PredicateType: types.CosignSignPredicateType,
	}

	payload, err := protojson.Marshal(statement)
	if err != nil {
		return err
	}

	if ko.SigningConfig != nil {
		var keypair sign.Keypair
		var ephemeralKeypair bool
		var idToken string
		var sv *SignerVerifier
		var err error

		if ko.Sk || ko.Slot != "" || ko.KeyRef != "" || signOpts.Cert != "" {
			sv, _, err = SignerFromKeyOpts(ctx, signOpts.Cert, signOpts.CertChain, ko)
			if err != nil {
				return fmt.Errorf("getting signer: %w", err)
			}
			keypair, err = key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
			if err != nil {
				return fmt.Errorf("creating signerverifier keypair: %w", err)
			}
		} else {
			keypair, err = sign.NewEphemeralKeypair(nil)
			if err != nil {
				return fmt.Errorf("generating keypair: %w", err)
			}
			ephemeralKeypair = true
		}
		defer func() {
			if sv != nil {
				sv.Close()
			}
		}()

		if ephemeralKeypair || ko.IssueCertificateForExistingKey {
			idToken, err = auth.RetrieveIDToken(ctx, auth.IDTokenConfig{
				TokenOrPath:      ko.IDToken,
				DisableProviders: ko.OIDCDisableProviders,
				Provider:         ko.OIDCProvider,
				AuthFlow:         ko.FulcioAuthFlow,
				SkipConfirm:      ko.SkipConfirmation,
				OIDCServices:     ko.SigningConfig.OIDCProviderURLs(),
				ClientID:         ko.OIDCClientID,
				ClientSecret:     ko.OIDCClientSecret,
				RedirectURL:      ko.OIDCRedirectURL,
			})
			if err != nil {
				return fmt.Errorf("retrieving ID token: %w", err)
			}
		}

		content := &sign.DSSEData{
			Data:        payload,
			PayloadType: "application/vnd.in-toto+json",
		}
		bundle, err := cbundle.SignData(ctx, content, keypair, idToken, ko.SigningConfig, ko.TrustedMaterial)
		if err != nil {
			return fmt.Errorf("signing bundle: %w", err)
		}

		regOpts := signOpts.Registry
		ociremoteOpts, err := regOpts.ClientOpts(ctx)
		if err != nil {
			return fmt.Errorf("constructing client options: %w", err)
		}
		return ociremote.WriteAttestationNewBundleFormat(digest, bundle, types.CosignSignPredicateType, ociremoteOpts...)
	}

	sv, genKey, err := SignerFromKeyOpts(ctx, signOpts.Cert, signOpts.CertChain, ko)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	if genKey || ko.IssueCertificateForExistingKey {
		sv, err = KeylessSigner(ctx, ko, sv)
		if err != nil {
			return fmt.Errorf("getting Fulcio signer: %w", err)
		}
	}
	defer sv.Close()

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	var timestampBytes []byte
	if ko.TSAServerURL != "" {
		tsaPayload, err := cosign.GetDSSESigBytes(signedPayload)
		if err != nil {
			return err
		}
		tc := client.NewTSAClient(ko.TSAServerURL)
		if ko.TSAClientCert != "" {
			tc = client.NewTSAClientMTLS(ko.TSAServerURL,
				ko.TSAClientCACert,
				ko.TSAClientCert,
				ko.TSAClientKey,
				ko.TSAServerName,
			)
		}
		timestampBytes, err = tsa.GetTimestampedSignature(tsaPayload, tc)
		if err != nil {
			return err
		}
	}

	signerBytes, err := sv.Bytes(ctx)
	if err != nil {
		return err
	}

	var rekorEntry *models.LogEntryAnon
	shouldUpload, err := ShouldUploadToTlog(ctx, ko, digest, signOpts.TlogUpload)
	if err != nil {
		return fmt.Errorf("should upload to tlog: %w", err)
	}
	if shouldUpload {
		rClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return err
		}
		rekorEntry, err = cosign.TLogUploadDSSEEnvelope(ctx, rClient, signedPayload, signerBytes)
		if err != nil {
			return err
		}
	}

	regOpts := signOpts.Registry
	ociremoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("constructing client options: %w", err)
	}

	pubKey, err := sv.PublicKey()
	if err != nil {
		return err
	}

	bundleBytes, err := cbundle.MakeNewBundle(pubKey, rekorEntry, payload, signedPayload, signerBytes, timestampBytes)
	if err != nil {
		return err
	}
	return ociremote.WriteAttestationNewBundleFormat(digest, bundleBytes, types.CosignSignPredicateType, ociremoteOpts...)
}

func signerFromSecurityKey(ctx context.Context, keySlot string) (*SignerVerifier, error) {
	sk, err := pivkey.GetKeyWithSlot(keySlot)
	if err != nil {
		return nil, err
	}
	sv, err := sk.SignerVerifier()
	if err != nil {
		sk.Close()
		return nil, err
	}

	// Handle the -cert flag.
	// With PIV, we assume the certificate is in the same slot on the PIV
	// token as the private key. If it's not there, show a warning to the
	// user.
	certFromPIV, err := sk.Certificate()
	var pemBytes []byte
	if err != nil {
		ui.Warnf(ctx, "no x509 certificate retrieved from the PIV token")
	} else {
		pemBytes, err = cryptoutils.MarshalCertificateToPEM(certFromPIV)
		if err != nil {
			sk.Close()
			return nil, err
		}
	}

	return &SignerVerifier{
		Cert:           pemBytes,
		SignerVerifier: sv,
		close:          sk.Close,
	}, nil
}

func signerFromKeyRef(ctx context.Context, certPath, certChainPath, keyRef string, passFunc cosign.PassFunc, defaultLoadOptions *[]signature.LoadOption) (*SignerVerifier, error) {
	k, err := sigs.SignerVerifierFromKeyRef(ctx, keyRef, passFunc, defaultLoadOptions)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	certSigner := &SignerVerifier{
		SignerVerifier: k,
	}

	var leafCert *x509.Certificate

	// Attempt to extract certificate from PKCS11 token
	// With PKCS11, we assume the certificate is in the same slot on the PKCS11
	// token as the private key. If it's not there, show a warning to the
	// user.
	if pkcs11Key, ok := k.(*pkcs11key.Key); ok {
		certFromPKCS11, _ := pkcs11Key.Certificate()
		certSigner.close = pkcs11Key.Close

		if certFromPKCS11 == nil {
			ui.Warnf(ctx, "no x509 certificate retrieved from the PKCS11 token")
		} else {
			pemBytes, err := cryptoutils.MarshalCertificateToPEM(certFromPKCS11)
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			// Check that the provided public key and certificate key match
			pubKey, err := k.PublicKey()
			if err != nil {
				pkcs11Key.Close()
				return nil, err
			}
			if cryptoutils.EqualKeys(pubKey, certFromPKCS11.PublicKey) != nil {
				pkcs11Key.Close()
				return nil, errors.New("pkcs11 key and certificate do not match")
			}
			leafCert = certFromPKCS11
			certSigner.Cert = pemBytes
		}
	}

	// Handle --cert flag
	if certPath != "" {
		// Allow both DER and PEM encoding
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		// Handle PEM
		if bytes.HasPrefix(certBytes, []byte("-----")) {
			decoded, _ := pem.Decode(certBytes)
			if decoded.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("supplied PEM file is not a certificate: %s", certPath)
			}
			certBytes = decoded.Bytes
		}
		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parse x509 certificate: %w", err)
		}
		pk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
		if cryptoutils.EqualKeys(pk, parsedCert.PublicKey) != nil {
			return nil, errors.New("public key in certificate does not match the provided public key")
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(parsedCert)
		if err != nil {
			return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
		}
		if certSigner.Cert != nil {
			ui.Warnf(ctx, "overriding x509 certificate retrieved from the PKCS11 token")
		}
		leafCert = parsedCert
		certSigner.Cert = pemBytes
	}

	if certChainPath == "" {
		return certSigner, nil
	} else if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	// Handle --cert-chain flag
	// Accept only PEM encoded certificate chain
	certChainBytes, err := os.ReadFile(certChainPath)
	if err != nil {
		return nil, fmt.Errorf("reading certificate chain from path: %w", err)
	}
	certChain, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(certChainBytes))
	if err != nil {
		return nil, fmt.Errorf("loading certificate chain: %w", err)
	}
	if len(certChain) == 0 {
		return nil, errors.New("no certificates in certificate chain")
	}
	// Verify certificate chain is valid
	rootPool := x509.NewCertPool()
	rootPool.AddCert(certChain[len(certChain)-1])
	subPool := x509.NewCertPool()
	for _, c := range certChain[:len(certChain)-1] {
		subPool.AddCert(c)
	}
	if _, err := cosign.TrustedCert(leafCert, rootPool, subPool); err != nil {
		return nil, fmt.Errorf("unable to validate certificate chain: %w", err)
	}
	certSigner.Chain = certChainBytes

	return certSigner, nil
}

func signerFromNewKey() (*SignerVerifier, error) {
	privKey, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating cert: %w", err)
	}
	sv, err := signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &SignerVerifier{
		SignerVerifier: sv,
	}, nil
}

func KeylessSigner(ctx context.Context, ko options.KeyOpts, sv *SignerVerifier) (*SignerVerifier, error) {
	var (
		k   *fulcio.Signer
		err error
	)

	if _, ok := sv.SignerVerifier.(*signature.ED25519phSignerVerifier); ok {
		return nil, fmt.Errorf("ed25519ph unsupported by Fulcio")
	}

	if ko.InsecureSkipFulcioVerify {
		if k, err = fulcio.NewSigner(ctx, ko, sv); err != nil {
			return nil, fmt.Errorf("getting key from Fulcio: %w", err)
		}
	} else {
		if k, err = fulcioverifier.NewSigner(ctx, ko, sv); err != nil {
			return nil, fmt.Errorf("getting key from Fulcio: %w", err)
		}
	}

	return &SignerVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

func SignerFromKeyOpts(ctx context.Context, certPath string, certChainPath string, ko options.KeyOpts) (*SignerVerifier, bool, error) {
	var sv *SignerVerifier
	var err error
	genKey := false
	switch {
	case ko.Sk:
		sv, err = signerFromSecurityKey(ctx, ko.Slot)
	case ko.KeyRef != "":
		sv, err = signerFromKeyRef(ctx, certPath, certChainPath, ko.KeyRef, ko.PassFunc, ko.DefaultLoadOptions)
	default:
		genKey = true
		ui.Infof(ctx, "Generating ephemeral keys...")
		sv, err = signerFromNewKey()
	}
	if err != nil {
		return nil, false, err
	}
	return sv, genKey, nil
}

type SignerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
	close func()
}

func (c *SignerVerifier) Close() {
	if c.close != nil {
		c.close()
	}
}

func (c *SignerVerifier) Bytes(ctx context.Context) ([]byte, error) {
	if c.Cert != nil {
		return c.Cert, nil
	}

	pemBytes, err := sigs.PublicKeyPem(c, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	return pemBytes, nil
}
