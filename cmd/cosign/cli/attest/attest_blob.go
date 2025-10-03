// Copyright 2022 The Sigstore Authors.
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

package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/rekor"
	cosign_sign "github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	tsaclient "github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v3/internal/ui"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/attestation"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
	sigstoredsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
type AttestBlobCommand struct {
	options.KeyOpts
	CertPath      string
	CertChainPath string

	ArtifactHash string

	StatementPath string
	PredicatePath string
	PredicateType string

	TlogUpload bool
	Timeout    time.Duration

	RekorEntryType string
}

// nolint
func (c *AttestBlobCommand) Exec(ctx context.Context, artifactPath string) error {
	// We can't have both a key and a security key
	if options.NOf(c.KeyRef, c.Sk) > 1 {
		return &options.KeyParseError{}
	}

	if options.NOf(c.PredicatePath, c.StatementPath) != 1 {
		return fmt.Errorf("one of --predicate or --statement must be set")
	}

	if c.RekorEntryType != "dsse" && c.RekorEntryType != "intoto" {
		return fmt.Errorf("unknown value for rekor-entry-type")
	}

	if c.Timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, c.Timeout)
		defer cancelFn()
	}

	base := path.Base(artifactPath)

	var payload []byte
	var err error

	if c.StatementPath != "" {
		fmt.Fprintln(os.Stderr, "Using statement from:", c.StatementPath)
		payload, err = os.ReadFile(filepath.Clean(c.StatementPath))
		if err != nil {
			return fmt.Errorf("could not read statement: %w", err)
		}
		if _, err := validateStatement(payload); err != nil {
			return fmt.Errorf("invalid statement: %w", err)
		}

	} else {
		var artifact []byte
		var hexDigest string
		if c.ArtifactHash == "" {
			if artifactPath == "-" {
				artifact, err = io.ReadAll(os.Stdin)
			} else {
				fmt.Fprintln(os.Stderr, "Using payload from:", artifactPath)
				artifact, err = os.ReadFile(filepath.Clean(artifactPath))
			}
			if err != nil {
				return err
			}
		}

		if c.ArtifactHash == "" {
			digest, _, err := signature.ComputeDigestForSigning(bytes.NewReader(artifact), crypto.SHA256, []crypto.Hash{crypto.SHA256, crypto.SHA384})
			if err != nil {
				return err
			}
			hexDigest = strings.ToLower(hex.EncodeToString(digest))
		} else {
			hexDigest = c.ArtifactHash
		}
		predicate, err := predicateReader(c.PredicatePath)
		if err != nil {
			return fmt.Errorf("getting predicate reader: %w", err)
		}
		defer predicate.Close()
		sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
			Predicate: predicate,
			Type:      c.PredicateType,
			Digest:    hexDigest,
			Repo:      base,
		})
		if err != nil {
			return err
		}
		payload, err = json.Marshal(sh)
		if err != nil {
			return err
		}
	}

	if c.SigningConfig != nil {
		var keypair sign.Keypair
		var ephemeralKeypair bool
		var idToken string
		var sv *cosign_sign.SignerVerifier
		var err error

		if c.Sk || c.Slot != "" || c.KeyRef != "" || c.CertPath != "" {
			sv, _, err = cosign_sign.SignerFromKeyOpts(ctx, c.CertPath, c.CertChainPath, c.KeyOpts)
			if err != nil {
				return fmt.Errorf("getting signer: %w", err)
			}
			keypair, err = key.NewSignerVerifierKeypair(sv, c.DefaultLoadOptions)
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

		if ephemeralKeypair || c.IssueCertificateForExistingKey {
			idToken, err = auth.RetrieveIDToken(ctx, auth.IDTokenConfig{
				TokenOrPath:      c.IDToken,
				DisableProviders: c.OIDCDisableProviders,
				Provider:         c.OIDCProvider,
				AuthFlow:         c.FulcioAuthFlow,
				SkipConfirm:      c.SkipConfirmation,
				OIDCServices:     c.SigningConfig.OIDCProviderURLs(),
				ClientID:         c.OIDCClientID,
				ClientSecret:     c.OIDCClientSecret,
				RedirectURL:      c.OIDCRedirectURL,
			})
			if err != nil {
				return fmt.Errorf("retrieving ID token: %w", err)
			}
		}

		content := &sign.DSSEData{
			Data:        payload,
			PayloadType: "application/vnd.in-toto+json",
		}
		bundle, err := cbundle.SignData(ctx, content, keypair, idToken, c.SigningConfig, c.TrustedMaterial)
		if err != nil {
			return fmt.Errorf("signing bundle: %w", err)
		}
		if err := os.WriteFile(c.BundlePath, bundle, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", c.BundlePath)
		return nil
	}

	sv, genKey, err := cosign_sign.SignerFromKeyOpts(ctx, c.CertPath, c.CertChainPath, c.KeyOpts)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	if genKey || c.IssueCertificateForExistingKey {
		sv, err = cosign_sign.KeylessSigner(ctx, c.KeyOpts, sv)
		if err != nil {
			return fmt.Errorf("getting Fulcio signer: %w", err)
		}
	}
	defer sv.Close()
	wrapped := sigstoredsse.WrapSigner(sv, types.IntotoPayloadType)

	sig, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	var timestampBytes []byte
	var tsaPayload []byte
	var rekorEntry *models.LogEntryAnon

	if c.KeyOpts.TSAServerURL != "" {
		tc := tsaclient.NewTSAClient(c.KeyOpts.TSAServerURL)
		if c.TSAClientCert != "" {
			tc = tsaclient.NewTSAClientMTLS(c.KeyOpts.TSAServerURL,
				c.KeyOpts.TSAClientCACert,
				c.KeyOpts.TSAClientCert,
				c.KeyOpts.TSAClientKey,
				c.KeyOpts.TSAServerName,
			)
		}
		tsaPayload, err = cosign.GetDSSESigBytes(sig)
		if err != nil {
			return err
		}
		timestampBytes, err = tsa.GetTimestampedSignature(tsaPayload, tc)
		if err != nil {
			return err
		}
		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(timestampBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return fmt.Errorf("rfc3161 timestamp is nil")
		}
	}

	signer, err := sv.Bytes(ctx)
	if err != nil {
		return err
	}
	shouldUpload, err := cosign_sign.ShouldUploadToTlog(ctx, c.KeyOpts, nil, c.TlogUpload)
	if err != nil {
		return fmt.Errorf("upload to tlog: %w", err)
	}
	signedPayload := cosign.LocalSignedPayload{}
	if shouldUpload {
		rekorClient, err := rekor.NewClient(c.RekorURL)
		if err != nil {
			return err
		}
		if c.RekorEntryType == "intoto" {
			rekorEntry, err = cosign.TLogUploadInTotoAttestation(ctx, rekorClient, sig, signer)
		} else {
			rekorEntry, err = cosign.TLogUploadDSSEEnvelope(ctx, rekorClient, sig, signer)
		}

		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "tlog entry created with index:", *rekorEntry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(rekorEntry)
	}

	if c.BundlePath != "" {
		var contents []byte
		pubKey, err := sv.PublicKey()
		if err != nil {
			return err
		}

		contents, err = cbundle.MakeNewBundle(pubKey, rekorEntry, payload, sig, signer, timestampBytes)
		if err != nil {
			return err
		}

		if err := os.WriteFile(c.BundlePath, contents, 0600); err != nil {
			return fmt.Errorf("create bundle file: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Bundle wrote in the file ", c.BundlePath)
	}

	fmt.Fprintln(os.Stdout, string(sig))

	return nil
}

func validateStatement(payload []byte) (string, error) {
	var statement *intotov1.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return "", fmt.Errorf("invalid statement: %w", err)
	}
	return statement.PredicateType, nil
}
