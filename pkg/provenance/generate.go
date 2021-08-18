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

	"github.com/gajananan/argocd-interlace/pkg/utils"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/pkg/ssl"
	"github.com/sigstore/cosign/pkg/cosign"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/encrypted"
	"golang.org/x/term"
)

type IntotoSigner struct {
	priv *ecdsa.PrivateKey
}

const (
	cli         = "/usr/local/bin/rekor-cli"
	server      = "../rekor-server"
	nodeDataDir = "node"
)

type SignOpts struct {
	Pf cosign.PassFunc
}

var (
	// Read is for fuzzing
	Read = readPasswordFn
)

func GenerateProvanance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha, imageRef string, buildStartedOn, buildFinishedOn time.Time) {

	subjects := []in_toto.Subject{}
	productName := imageRef

	digest, err := getDigest(productName)
	if err != nil {
		log.Info("Error in getting digest: %s ", err.Error())
	}

	digest = strings.ReplaceAll(digest, "sha256:", "")
	log.Info("digest ", digest)
	subjects = append(subjects, in_toto.Subject{Name: productName,
		Digest: in_toto.DigestSet{
			"sha256": digest,
		},
	})

	materials := generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha)

	entryPoint := "argocd-interlace"
	recipe := in_toto.ProvenanceRecipe{
		EntryPoint: entryPoint,
		Arguments:  []string{"-n argocd"},
	}

	it := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateProvenanceV01,
			Subject:       subjects,
		},
		Predicate: in_toto.ProvenancePredicate{
			Metadata: in_toto.ProvenanceMetadata{
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
		log.Info("Error in marshaling attestation:  %s", err.Error())
	}

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	utils.WriteToFile(string(b), appDirPath, utils.PROVENANCE_FILE_NAME)

	generateSignedAttestation(it, appDirPath)

}

func getDigest(src string) (string, error) {

	digest, err := crane.Digest(src)
	if err != nil {
		return "", fmt.Errorf("fetching digest %s: %v", src, err)
	}
	return digest, nil
}

func generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha string) []in_toto.ProvenanceMaterial {

	materials := []in_toto.ProvenanceMaterial{}

	materials = append(materials, in_toto.ProvenanceMaterial{
		URI: appSourceRepoUrl,
		Digest: in_toto.DigestSet{
			"commit":   string(appSourceCommitSha),
			"revision": appSourceRevision,
			"path":     appPath,
		},
	})

	return materials
}

func generateSignedAttestation(it in_toto.Statement, appDirPath string) {

	b, err := json.Marshal(it)
	if err != nil {
		log.Info("Error in marshaling attestation:  %s", err.Error())
		return
	}

	ecdsaPriv, _ := ioutil.ReadFile(filepath.Clean(utils.PRIVATE_KEY_PATH))

	pb, _ := pem.Decode(ecdsaPriv)

	pwd := "" //os.Getenv(cosignPwd) //GetPass(true)

	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))

	if err != nil {
		log.Info("Error in dycrypting private key")
		return
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)

	if err != nil {
		log.Info("Error in parsing private key")
		return
	}

	signer, err := ssl.NewEnvelopeSigner(&IntotoSigner{
		priv: priv.(*ecdsa.PrivateKey),
	})
	if err != nil {
		log.Info("Error in creating new signer")
		return
	}

	env, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		log.Info("Error in signing payload")
		return
	}

	// Now verify
	err = signer.Verify(env)
	if err != nil {
		log.Info("Error in verifying env")
		return
	}

	eb, err := json.Marshal(env)
	if err != nil {
		log.Info("Error in marshaling env")
		return
	}

	log.Debug("attestation.json", string(eb))

	utils.WriteToFile(string(eb), appDirPath, utils.ATTESTATION_FILE_NAME)

	attestationPath := filepath.Join(appDirPath, utils.ATTESTATION_FILE_NAME)

	upload(it, attestationPath)

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

func upload(it in_toto.Statement, attestationPath string) {

	pubKeyPath := utils.PUB_KEY_PATH
	// If we do it twice, it should already exist
	out := runCli("upload", "--artifact", attestationPath, "--type", "intoto", "--public-key", pubKeyPath, "--pki-format", "x509")

	outputContains(out, "Created entry at")

	uuid := getUUIDFromUploadOutput(out)

	log.Info("Uploaded attestation to tlog,  uuid: %s", uuid)
}

func outputContains(output, sub string) {

	if !strings.Contains(output, sub) {
		log.Info(fmt.Sprintf("Expected [%s] in response, got %s", sub, output))
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

	arg = append(arg, "--rekor_server=https://rekor.sigstore.dev")
	// use a blank config file to ensure no collision
	if os.Getenv("REKORTMPDIR") != "" {
		arg = append(arg, "--config="+os.Getenv("REKORTMPDIR")+".rekor.yaml")
	}
	return run("", cli, arg...)

}

func run(stdin, cmd string, arg ...string) string {

	c := exec.Command(cmd, arg...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	if os.Getenv("REKORTMPDIR") != "" {
		// ensure that we use a clean state.json file for each run
		c.Env = append(c.Env, "HOME="+os.Getenv("REKORTMPDIR"))
	}
	b, err := c.CombinedOutput()
	if err != nil {
		log.Info("Error in executing CLI: %s", string(b))
	}
	return string(b)
}
