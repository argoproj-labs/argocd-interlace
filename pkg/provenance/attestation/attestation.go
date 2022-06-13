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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/encrypted"
	"golang.org/x/term"
)

type IntotoSigner struct {
	priv *ecdsa.PrivateKey
}

const (
	cli              = "/usr/local/bin/rekor-cli"
	publicKeyPEMType = "PUBLIC KEY"
)

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

func GenerateSignedAttestation(it in_toto.Statement, appName, appDirPath string, uploadTLog bool) (*provenance.ProvenanceRef, error) {

	b, err := json.Marshal(it)
	if err != nil {
		log.Errorf("Error in marshaling attestation:  %s", err.Error())
		return nil, err
	}

	ecdsaPriv, err := ioutil.ReadFile(filepath.Clean(config.PRIVATE_KEY_PATH))
	if err != nil {
		log.Errorf("Error in reading private key:  %s", err.Error())
		return nil, err
	}

	pb, _ := pem.Decode(ecdsaPriv)

	pwd := ""

	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))

	if err != nil {
		log.Errorf("Error in dycrypting private key: %s", err.Error())
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)

	if err != nil {
		log.Errorf("Error in parsing private key: %s", err.Error())
		return nil, err
	}

	intotoSigner := &IntotoSigner{
		priv: priv.(*ecdsa.PrivateKey),
	}
	signer, err := dsse.NewEnvelopeSigner(intotoSigner)
	if err != nil {
		log.Errorf("Error in creating new signer: %s", err.Error())
		return nil, err
	}

	env, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		log.Errorf("Error in signing payload: %s", err.Error())
		return nil, err
	}

	// Now verify
	_, err = signer.Verify(env)
	if err != nil {
		log.Errorf("Error in verifying env: %s", err.Error())
		return nil, err
	}

	eb, err := json.Marshal(env)
	if err != nil {
		log.Errorf("Error in marshaling env: %s", err.Error())
		return nil, err
	}

	log.Debug("attestation.json", string(eb))

	err = utils.WriteToFile(string(eb), appDirPath, config.ATTESTATION_FILE_NAME)
	if err != nil {
		log.Errorf("Error in writing attestation to a file: %s", err.Error())
		return nil, err
	}

	attestationPath := filepath.Join(appDirPath, config.ATTESTATION_FILE_NAME)

	var provRef *provenance.ProvenanceRef
	if uploadTLog {
		// public key file is required to upload the attestation
		pub := intotoSigner.Public()
		pubkeyPath, err := savePubkey(pub)
		if err != nil {
			log.Errorf("Error in saving public key: %s", err.Error())
			return nil, err
		}
		defer os.Remove(pubkeyPath)
		provRef = upload(it, attestationPath, appName, pubkeyPath)
	}

	return provRef, nil

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
	return "no-keyid", nil
}

func (it *IntotoSigner) Public() crypto.PublicKey {
	return it.priv.Public()
}

func upload(it in_toto.Statement, attestationPath, appName, pubkeyPath string) *provenance.ProvenanceRef {
	// If we do it twice, it should already exist
	out := runCli("upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubkeyPath, "--pki-format", "x509")

	outputContains(out, "Created entry at")

	uuid, url := getUUIDFromUploadOutput(out)

	log.Infof("[INFO][%s] Interlace generated provenance record of manifest build with uuid: %s, url: %s", appName, uuid, url)

	log.Infof("[INFO][%s] Interlace stores attestation to provenance record to Rekor transparency log", appName)

	log.Infof("[INFO][%s] %s", appName, out)

	if uuid != "" && url != "" {
		return &provenance.ProvenanceRef{UUID: uuid, URL: url}
	}
	return nil
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

func runCli(arg ...string) string {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return ""
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

func run(stdin, cmd string, arg ...string) string {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return ""
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
		log.Errorf("Error in executing CLI: %s", string(b))
	}
	return string(b)
}

func savePubkey(pubkey crypto.PublicKey) (string, error) {
	f, err := ioutil.TempFile("", "publickey")
	if err != nil {
		return "", err
	}
	pubkeyPEM, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  publicKeyPEMType,
		Bytes: pubkeyPEM,
	}
	err = pem.Encode(f, pemBlock)
	if err != nil {
		return "", err
	}
	pubkeyPath, err := filepath.Abs(f.Name())
	if err != nil {
		return "", err
	}
	return pubkeyPath, nil
}
