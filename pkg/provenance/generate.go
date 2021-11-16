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

package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/utils"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/cosign"
	kustbuildutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/manifestbuild/kustomize"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/encrypted"
	"github.com/tidwall/gjson"
	"golang.org/x/term"
)

type IntotoSigner struct {
	priv *ecdsa.PrivateKey
}

const (
	cli = "/usr/local/bin/rekor-cli"
)

type SignOpts struct {
	Pf cosign.PassFunc
}

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

func GenerateProvanance(appName, appPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreviousCommitSha,
	target, targetDigest string, buildStartedOn, buildFinishedOn time.Time, uploadTLog bool) error {

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	manifestFile := filepath.Join(appDirPath, utils.MANIFEST_FILE_NAME)
	recipeCmds := []string{"", ""}

	host, orgRepo, path, gitRef, gitSuff := ParseGitUrl(appSourceRepoUrl)
	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff
	log.Info("url:", url)
	r, err := GetTopGitRepo(url)

	if err != nil {
		log.Errorf("Error git clone:  %s", err.Error())
		return err
	}
	log.Info("r.RootDir ", r.RootDir, "appPath ", appPath)

	baseDir := filepath.Join(r.RootDir, appPath)

	prov, err := kustbuildutil.GenerateProvenance(manifestFile, "", baseDir, buildStartedOn, buildFinishedOn, recipeCmds)

	if err != nil {
		log.Infof("err in prov: %s ", err.Error())
	}

	provBytes, err := json.Marshal(prov)
	log.Infof(": prov: %s ", string(provBytes))

	subjects := []in_toto.Subject{}

	targetDigest = strings.ReplaceAll(targetDigest, "sha256:", "")
	subjects = append(subjects, in_toto.Subject{Name: target,
		Digest: in_toto.DigestSet{
			"sha256": targetDigest,
		},
	})

	materials := generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha, string(provBytes))
	interlaceConfig, err := config.GetInterlaceConfig()
	argocdNamespace := interlaceConfig.ArgocdNamespace

	entryPoint := "argocd-interlace"
	recipe := in_toto.ProvenanceRecipe{
		EntryPoint: entryPoint,
		Arguments:  []string{"-n " + argocdNamespace},
	}

	it := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateSLSAProvenanceV01,
			Subject:       subjects,
		},
		Predicate: in_toto.ProvenancePredicate{
			Metadata: &in_toto.ProvenanceMetadata{
				Reproducible:    true,
				BuildStartedOn:  &buildStartedOn,
				BuildFinishedOn: &buildFinishedOn,
			},

			Materials: materials,
			Recipe:    recipe,
		},
	}
	b, err := json.Marshal(it)
	if err != nil {
		log.Errorf("Error in marshaling attestation:  %s", err.Error())
		return err
	}

	err = utils.WriteToFile(string(b), appDirPath, utils.PROVENANCE_FILE_NAME)
	if err != nil {
		log.Errorf("Error in writing provenance to a file:  %s", err.Error())
		return err
	}

	err = generateSignedAttestation(it, appName, appDirPath, uploadTLog)
	if err != nil {
		log.Errorf("Error in generating signed attestation:  %s", err.Error())
		return err
	}

	return nil
}

func generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha string, provTrace string) []in_toto.ProvenanceMaterial {

	materials := []in_toto.ProvenanceMaterial{}

	materials = append(materials, in_toto.ProvenanceMaterial{
		URI: appSourceRepoUrl + ".git",
		Digest: in_toto.DigestSet{
			"commit":   string(appSourceCommitSha),
			"revision": appSourceRevision,
			"path":     appPath,
		},
	})

	appSourceRepoUrlFul := appSourceRepoUrl + ".git"
	materialsStr := gjson.Get(provTrace, "predicate.materials")

	for _, mat := range materialsStr.Array() {

		uri := gjson.Get(mat.String(), "uri").String()
		path := gjson.Get(mat.String(), "digest.path").String()
		revision := gjson.Get(mat.String(), "digest.revision").String()
		commit := gjson.Get(mat.String(), "digest.commit").String()

		if uri != appSourceRepoUrlFul {
			intoMat := in_toto.ProvenanceMaterial{
				URI: uri,
				Digest: in_toto.DigestSet{
					"commit":   commit,
					"revision": revision,
					"path":     path,
				},
			}
			materials = append(materials, intoMat)
		}
	}

	return materials
}

func generateSignedAttestation(it in_toto.Statement, appName, appDirPath string, uploadTLog bool) error {

	b, err := json.Marshal(it)
	if err != nil {
		log.Errorf("Error in marshaling attestation:  %s", err.Error())
		return err
	}

	ecdsaPriv, err := ioutil.ReadFile(filepath.Clean(utils.PRIVATE_KEY_PATH))
	if err != nil {
		log.Errorf("Error in reading private key:  %s", err.Error())
		return err
	}

	pb, _ := pem.Decode(ecdsaPriv)

	pwd := ""

	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))

	if err != nil {
		log.Errorf("Error in dycrypting private key: %s", err.Error())
		return err
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)

	if err != nil {
		log.Errorf("Error in parsing private key: %s", err.Error())
		return err
	}

	signer, err := dsse.NewEnvelopeSigner(&IntotoSigner{
		priv: priv.(*ecdsa.PrivateKey),
	})
	if err != nil {
		log.Errorf("Error in creating new signer: %s", err.Error())
		return err
	}

	env, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		log.Errorf("Error in signing payload: %s", err.Error())
		return err
	}

	// Now verify
	err = signer.Verify(env)
	if err != nil {
		log.Errorf("Error in verifying env: %s", err.Error())
		return err
	}

	eb, err := json.Marshal(env)
	if err != nil {
		log.Errorf("Error in marshaling env: %s", err.Error())
		return err
	}

	log.Debug("attestation.json", string(eb))

	err = utils.WriteToFile(string(eb), appDirPath, utils.ATTESTATION_FILE_NAME)
	if err != nil {
		log.Errorf("Error in writing attestation to a file: %s", err.Error())
		return err
	}

	attestationPath := filepath.Join(appDirPath, utils.ATTESTATION_FILE_NAME)

	if uploadTLog {
		upload(it, attestationPath, appName)
	}

	return nil

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

func (it *IntotoSigner) Sign(data []byte) ([]byte, string, error) {
	h := sha256.Sum256(data)
	sig, err := it.priv.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, "", err
	}
	return sig, "", nil
}

func (it *IntotoSigner) Verify(_ string, data, sig []byte) error {
	h := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(&it.priv.PublicKey, h[:], sig)
	if ok {
		return nil
	}
	return errors.New("invalid signature")
}

func upload(it in_toto.Statement, attestationPath, appName string) {

	pubKeyPath := utils.PUB_KEY_PATH
	// If we do it twice, it should already exist
	out := runCli("upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath, "--pki-format", "x509")

	outputContains(out, "Created entry at")

	_ = getUUIDFromUploadOutput(out)

	log.Infof("[INFO][%s] Interlace generated provenance record of manifest build", appName)

	log.Infof("[INFO][%s] Interlace stores attestation to provenance record to Rekor transparency log", appName)

	log.Infof("[INFO][%s] %s", appName, out)

}

func outputContains(output, sub string) {

	if !strings.Contains(output, sub) {
		log.Infof(fmt.Sprintf("Expected [%s] in response, got %s", sub, output))
	}
}

func getUUIDFromUploadOutput(out string) string {

	// Output looks like "Artifact timestamped at ...\m Wrote response \n Created entry at index X, available at $URL/UUID", so grab the UUID:
	urlTokens := strings.Split(strings.TrimSpace(out), " ")
	url := urlTokens[len(urlTokens)-1]
	splitUrl := strings.Split(url, "/")
	return splitUrl[len(splitUrl)-1]
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
