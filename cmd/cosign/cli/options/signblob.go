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

package options

import (
	"github.com/spf13/cobra"
)

// SignBlobOptions is the top level wrapper for the sign-blob command.
// The new output-certificate flag is only in use when COSIGN_EXPERIMENTAL is enabled
type SignBlobOptions struct {
	Key              string
	SecurityKey      SecurityKeyOptions
	Fulcio           FulcioOptions
	Rekor            RekorOptions
	OIDC             OIDCOptions
	Registry         RegistryOptions
	BundlePath       string
	SkipConfirmation bool
	TlogUpload       bool
	TSAServerURL     string
	IssueCertificate bool

	UseSigningConfig  bool
	SigningConfigPath string
	TrustedRootPath   string
}

var _ Interface = (*SignBlobOptions)(nil)

// AddFlags implements Interface
func (o *SignBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Fulcio.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.OIDC.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the private key file, KMS URI or Kubernetes Secret")
	_ = cmd.MarkFlagFilename("key", privateKeyExts...)

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"write everything required to verify the blob to a FILE")
	_ = cmd.MarkFlagFilename("bundle", bundleExts...)

	// TODO: have this default to true as a breaking change
	cmd.Flags().BoolVar(&o.UseSigningConfig, "use-signing-config", false,
		"whether to use a TUF-provided signing config for the service URLs. Must provide --bundle, which will output verification material in the new format")

	cmd.Flags().StringVar(&o.SigningConfigPath, "signing-config", "",
		"path to a signing config file. Must provide --bundle, which will output verification material in the new format")

	cmd.MarkFlagsMutuallyExclusive("use-signing-config", "signing-config")

	cmd.Flags().StringVar(&o.TrustedRootPath, "trusted-root", "",
		"optional path to a TrustedRoot JSON file to verify a signature after signing")

	cmd.Flags().BoolVarP(&o.SkipConfirmation, "yes", "y", false,
		"skip confirmation prompts for non-destructive operations")

	cmd.Flags().BoolVar(&o.TlogUpload, "tlog-upload", true,
		"whether or not to upload to the tlog")

	cmd.Flags().StringVar(&o.TSAServerURL, "timestamp-server-url", "",
		"url to the Timestamp RFC3161 server, default none. Must be the path to the API to request timestamp responses, e.g. https://freetsa.org/tsr")

	cmd.Flags().BoolVar(&o.IssueCertificate, "issue-certificate", false,
		"issue a code signing certificate from Fulcio, even if a key is provided")
}
