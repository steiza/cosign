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
	"context"
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/internal/auth"
	"github.com/sigstore/cosign/v3/internal/key"
	internal "github.com/sigstore/cosign/v3/internal/pkg/cosign"
	"github.com/sigstore/cosign/v3/internal/ui"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
)

func getPayload(ctx context.Context, payloadPath string, hashFunction crypto.Hash) (internal.HashReader, func() error, error) {
	if payloadPath == "-" {
		return internal.NewHashReader(os.Stdin, hashFunction), func() error { return nil }, nil
	}
	ui.Infof(ctx, "Using payload from: %s", payloadPath)
	f, err := os.Open(filepath.Clean(payloadPath))
	if err != nil {
		return internal.HashReader{}, nil, err
	}
	return internal.NewHashReader(f, hashFunction), f.Close, nil
}

// nolint
func SignBlobCmd(ro *options.RootOptions, ko options.KeyOpts, payloadPath string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader

	ctx, cancel := context.WithTimeout(context.Background(), ro.Timeout)
	defer cancel()

	shouldUpload, err := ShouldUploadToTlog(ctx, ko, nil, tlogUpload)
	if err != nil {
		return nil, fmt.Errorf("upload to tlog: %w", err)
	}

	if !shouldUpload {
		// To maintain backwards compatibility with older cosign versions,
		// we do not use ed25519ph for ed25519 keys when the signatures are not
		// uploaded to the Tlog.
		ko.DefaultLoadOptions = &[]signature.LoadOption{}
	}

	// XXX: assume we are using signing config; otherwise need to assemble from provided URLs
	// see https://github.com/sigstore/cosign/pull/4428
	var keypair sign.Keypair
	var ephemeralKeypair bool
	var idToken string
	var sv *SignerVerifier

	if ko.Sk || ko.Slot != "" || ko.KeyRef != "" {
		sv, _, err = SignerFromKeyOpts(ctx, "", "", ko)
		if err != nil {
			return nil, fmt.Errorf("getting signer: %w", err)
		}
		keypair, err = key.NewSignerVerifierKeypair(sv, ko.DefaultLoadOptions)
		if err != nil {
			return nil, fmt.Errorf("creating signerverifier keypair: %w", err)
		}
	} else {
		keypair, err = sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, fmt.Errorf("generating keypair: %w", err)
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
			return nil, fmt.Errorf("retrieving ID token: %w", err)
		}
	}

	payload, closePayload, err := getPayload(ctx, payloadPath, protoHashAlgoToHash(keypair.GetHashAlgorithm()))
	if err != nil {
		return nil, fmt.Errorf("getting payload: %w", err)
	}
	defer closePayload()
	data, err := io.ReadAll(&payload)
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	content := &sign.PlainData{
		Data: data,
	}
	bundle, err := cbundle.SignData(ctx, content, keypair, idToken, ko.SigningConfig, ko.TrustedMaterial)
	if err != nil {
		return nil, fmt.Errorf("signing bundle: %w", err)
	}
	if err := os.WriteFile(ko.BundlePath, bundle, 0600); err != nil {
		return nil, fmt.Errorf("create bundle file: %w", err)
	}
	ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	return bundle, nil
}

func protoHashAlgoToHash(hashFunc protocommon.HashAlgorithm) crypto.Hash {
	switch hashFunc {
	case protocommon.HashAlgorithm_SHA2_256:
		return crypto.SHA256
	case protocommon.HashAlgorithm_SHA2_384:
		return crypto.SHA384
	case protocommon.HashAlgorithm_SHA2_512:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}
