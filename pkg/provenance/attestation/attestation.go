//
// Copyright 2021 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	rekorapp "github.com/sigstore/rekor/cmd/rekor-cli/app"
	"github.com/sigstore/rekor/pkg/client"
	gen_client "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/encrypted"
	"golang.org/x/term"
)

const (
	defaultAttestationType = "intoto:0.0.1"
	defaultTimeountSeconds = 30
)

const (
	cli              = "/usr/local/bin/rekor-cli"
	publicKeyPEMType = "PUBLIC KEY"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

func GenerateSignedAttestation(it in_toto.Statement, appName, appDirPath string, privkeyBytes []byte, uploadTLog bool, rekorURL string) ([]byte, *provenance.ProvenanceRef, error) {

	b, err := json.Marshal(it)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal attestation")
	}

	// if signing key is empty, do not sign the provenance and return here
	if string(privkeyBytes) == "" {
		log.Warnf("signing key is empty, so skip signing the provenance & skip uploading the attestation")
		return nil, nil, nil
	}

	pb, _ := pem.Decode(privkeyBytes)

	pwd := ""

	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))

	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to decrypt private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)

	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse the private key")
	}

	intotoSigner := &IntotoSigner{
		priv: priv.(*ecdsa.PrivateKey),
	}
	signer, err := dsse.NewEnvelopeSigner(intotoSigner)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create new signer object for attestation")
	}

	env, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign the attestation payload")
	}

	var provSig []byte
	if len(env.Signatures) > 0 {
		provSig = []byte(env.Signatures[0].Sig)
	}

	// Now verify
	_, err = signer.Verify(env)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to verify the attestation after signing")
	}

	attestationBytes, err := json.Marshal(env)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal the attestation envelope")
	}

	log.Debug("attestation.json", string(attestationBytes))

	var provRef *provenance.ProvenanceRef
	if uploadTLog {
		// public key file is required to upload the attestation
		pub := intotoSigner.Public()
		pubkeyBytes, err := getPublicKeyBytes(pub)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to get public key bytes")
		}
		log.Infof("[DEBUG] public key: %s", string(pubkeyBytes))
		provRef, err = upload(rekorURL, attestationBytes, pubkeyBytes)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to upload the attestation to rekor")
		}
	}

	return provSig, provRef, nil

}

func readPasswordFn() func() ([]byte, error) {
	pw, ok := os.LookupEnv("COSIGN_PASSWORD")
	switch {
	case ok:
		return func() ([]byte, error) {
			return []byte(pw), nil
		}
	case term.IsTerminal(0):
		return func() ([]byte, error) {
			return term.ReadPassword(0)
		}
	// Handle piped in passwords.
	default:
		return func() ([]byte, error) {
			return ioutil.ReadAll(os.Stdin)
		}
	}
}

func GetPass(confirm bool) ([]byte, error) {
	read := Read()
	fmt.Fprint(os.Stderr, "Enter password for private key: ")
	pw1, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !confirm {
		return pw1, nil
	}
	fmt.Fprint(os.Stderr, "Enter again: ")
	pw2, err := read()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if string(pw1) != string(pw2) {
		return nil, errors.New("passwords do not match")
	}
	return pw1, nil
}

type IntotoSigner struct {
	priv *ecdsa.PrivateKey
}

func (it *IntotoSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	sig, err := it.priv.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (it *IntotoSigner) Verify(data, sig []byte) error {
	h := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(&it.priv.PublicKey, h[:], sig)
	if ok {
		return nil
	}
	return errors.New("invalid signature")
}

func (it *IntotoSigner) KeyID() (string, error) {
	return "", nil
}

func (it *IntotoSigner) Public() crypto.PublicKey {
	return it.priv.Public()
}

func upload(rekorURL string, attestationBytes, pubkeyBytes []byte) (*provenance.ProvenanceRef, error) {
	dir, err := os.MkdirTemp("", "attestation")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}
	defer os.RemoveAll(dir)

	attestationPath := filepath.Join(dir, "attestation.json")
	err = os.WriteFile(attestationPath, attestationBytes, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp attestation file")
	}

	pubkeyPath := filepath.Join(dir, "key.pub")
	err = os.WriteFile(pubkeyPath, pubkeyBytes, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp public key file")
	}

	rekorClient, err := client.GetRekorClient(rekorURL, client.WithUserAgent(rekorapp.UserAgent()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to get rekor client")
	}
	var entry models.ProposedEntry
	typeStr, versionStr, err := rekorapp.ParseTypeFlag(defaultAttestationType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse attestation type")
	}
	props := &types.ArtifactProperties{
		ArtifactPath:   &url.URL{Path: attestationPath},
		PublicKeyPaths: []*url.URL{{Path: pubkeyPath}},
		PKIFormat:      "x509",
	}
	entry, err = types.NewProposedEntry(context.Background(), typeStr, versionStr, *props)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	resp, err := tryUpload(rekorClient, entry)
	if err != nil {
		return nil, errors.Wrap(err, "failed to upload attestation entry")
	}
	var logEntry models.LogEntryAnon
	for _, entry := range resp.Payload {
		logEntry = entry
	}
	var uuid, url string
	if logEntry.LogID != nil {
		uuid = *logEntry.LogID
		url = rekorURL + "/api/v1/log/entries/" + uuid
	}
	return &provenance.ProvenanceRef{UUID: uuid, URL: url}, nil
}

func tryUpload(rekorClient *gen_client.Rekor, entry models.ProposedEntry) (*entries.CreateLogEntryCreated, error) {
	params := entries.NewCreateLogEntryParams()
	params.SetTimeout(time.Second * defaultTimeountSeconds)
	if pei, ok := entry.(types.ProposedEntryIterator); ok {
		params.SetProposedEntry(pei.Get())
	} else {
		params.SetProposedEntry(entry)
	}
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		if e, ok := err.(*entries.CreateLogEntryBadRequest); ok {
			if pei, ok := entry.(types.ProposedEntryIterator); ok {
				if pei.HasNext() {
					log.Errorf("failed to upload entry: %v", e)
					return tryUpload(rekorClient, pei.GetNext())
				}
			}
		}
		return nil, err
	}
	return resp, nil
}

func upload_cli(it in_toto.Statement, attestationPath, appName, pubkeyPath string) (*provenance.ProvenanceRef, error) {
	// If we do it twice, it should already exist
	out, err := runCli("upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubkeyPath, "--pki-format", "x509")
	if err != nil {
		return nil, errors.Wrap(err, "failed to upload attestation to rekor")
	}

	outputContains(out, "Created entry at")

	uuid, url := getUUIDFromUploadOutput(out)

	log.Infof("[%s] Interlace generated provenance record of manifest build with uuid: %s, url: %s", appName, uuid, url)

	log.Infof("[%s] Interlace stores attestation to provenance record to Rekor transparency log", appName)

	log.Infof("[%s] %s", appName, out)

	if uuid != "" && url != "" {
		return &provenance.ProvenanceRef{UUID: uuid, URL: url}, nil
	}
	return nil, errors.New("unknown error while uploading attestation to rekor")
}

func outputContains(output, sub string) {

	if !strings.Contains(output, sub) {
		log.Infof(fmt.Sprintf("Expected [%s] in response, got %s", sub, output))
	}
}

func getUUIDFromUploadOutput(out string) (string, string) {

	// Output looks like "Artifact timestamped at ...\m Wrote response \n Created entry at index X, available at $URL/UUID", so grab the UUID:
	// Example) Created entry at index 1587352, available at: https://rekor.sigstore.dev/api/v1/log/entries/d07107983ad1044259813fff2ff90e1f1a30009b4f43723f2205ad5d02ba43be\n
	parts := strings.Split(strings.TrimSpace(out), ", ")
	if len(parts) != 2 {
		return "", ""
	}
	uuid := strings.TrimSpace(strings.ReplaceAll(parts[0], "Created entry at index ", ""))
	url := strings.TrimSuffix(strings.TrimSpace(strings.ReplaceAll(parts[1], "available at: ", "")), "\n")
	return uuid, url
}

func runCli(arg ...string) (string, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to load interlace config")
	}

	rekorServer := interlaceConfig.RekorServer

	argStr := fmt.Sprintf("--rekor_server=%s", rekorServer)

	arg = append(arg, argStr)
	// use a blank config file to ensure no collision
	if interlaceConfig.RekorTmpDir != "" {
		arg = append(arg, "--config="+interlaceConfig.RekorTmpDir+".rekor.yaml")
	}
	return run("", cli, arg...)

}

func run(stdin, cmd string, arg ...string) (string, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		return "", errors.Wrap(err, "failed to load interlace config")
	}
	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if interlaceConfig.RekorTmpDir != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+interlaceConfig.RekorTmpDir)
	}
	b, err := c.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "failed to execute command \"%s %s\"", cmd, strings.Join(arg, " "))
	}
	return string(b), nil
}

func getPublicKeyBytes(pubkey crypto.PublicKey) ([]byte, error) {
	pubkeyPEM, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:  publicKeyPEMType,
		Bytes: pubkeyPEM,
	}
	pubkeyBytes := pem.EncodeToMemory(pemBlock)
	return pubkeyBytes, nil
}
