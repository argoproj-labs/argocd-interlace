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

package kustomize

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance/attestation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/gitutil"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/pkg/errors"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/encrypted"
	"github.com/tidwall/gjson"
)

type KustomizeProvenanceManager struct {
	appData application.ApplicationData
	prov    in_toto.Statement
	sig     []byte
	ref     provenance.ProvenanceRef
}

const (
	ProvenanceAnnotation = "kustomize"
)

const cosignPwdEnvKey = "COSIGN_PASSWORD"

func NewProvenanceManager(appData application.ApplicationData) (*KustomizeProvenanceManager, error) {
	return &KustomizeProvenanceManager{
		appData: appData,
	}, nil
}

func (p *KustomizeProvenanceManager) GenerateProvenance(target, targetDigest string, privkeyBytes []byte, uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error {
	appName := p.appData.AppName
	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl
	appSourceRevision := p.appData.AppSourceRevision
	appSourceCommitSha := p.appData.AppSourceCommitSha

	interlaceConfig, _ := config.GetInterlaceConfig()
	appDirPath := filepath.Join(interlaceConfig.WorkspaceDir, appName, appPath)

	manifestFile := filepath.Join(appDirPath, config.MANIFEST_FILE_NAME)
	recipeCmds := []string{"", ""}

	host, orgRepo, path, gitRef, gitSuff := gitutil.ParseGitUrl(appSourceRepoUrl)
	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff
	log.Info("url:", url)

	r, err := gitutil.GetTopGitRepo(url)

	if err != nil {
		return errors.Wrap(err, "failed to git clone")
	}

	log.Info("r.RootDir ", r.RootDir, "appPath ", appPath)

	baseDir := filepath.Join(r.RootDir, appPath)

	prov, err := GenerateProvenance(manifestFile, "", baseDir, buildStartedOn, buildFinishedOn, recipeCmds)

	if err != nil {
		log.Infof("err in prov: %s ", err.Error())
	}

	provBytes, err := json.Marshal(prov)
	if err != nil {
		return errors.Wrap(err, "failed to marshal provenance data")
	}

	subjects := []in_toto.Subject{}

	targetDigest = strings.ReplaceAll(targetDigest, "sha256:", "")
	subjects = append(subjects, in_toto.Subject{Name: target,
		Digest: intotoprov02.DigestSet{
			"sha256": targetDigest,
		},
	})

	materials := generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision,
		appSourceCommitSha, string(provBytes))

	entryPoint := "argocd-interlace"
	applicationBytes, err := json.Marshal(p.appData.Object)
	if err != nil {
		return errors.Wrap(err, "failed to marshal Application data")
	}
	invocation := intotoprov02.ProvenanceInvocation{
		ConfigSource: intotoprov02.ConfigSource{EntryPoint: entryPoint},
		Parameters:   map[string]string{"applicationSnapshot": string(applicationBytes)},
	}

	it := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: intotoprov02.PredicateSLSAProvenance,
			Subject:       subjects,
		},
		Predicate: intotoprov02.ProvenancePredicate{
			Metadata: &intotoprov02.ProvenanceMetadata{
				Reproducible:    true,
				BuildStartedOn:  &buildStartedOn,
				BuildFinishedOn: &buildFinishedOn,
			},

			Materials:  materials,
			Invocation: invocation,
		},
	}
	p.prov = it
	b, err := json.Marshal(it)
	if err != nil {
		return errors.Wrap(err, "failed to marshal attestation data")
	}

	err = utils.WriteToFile(string(b), appDirPath, config.PROVENANCE_FILE_NAME)
	if err != nil {
		return errors.Wrap(err, "failed to write the provenance to file")
	}

	provSig, provRef, err := attestation.GenerateSignedAttestation(it, appName, appDirPath, privkeyBytes, uploadTLog)
	if err != nil {
		return errors.Wrap(err, "failed to sign the attestation")
	}
	if provSig != nil {
		p.sig = provSig
	}
	if provRef != nil {
		p.ref = *provRef
	}

	return nil
}

func (p *KustomizeProvenanceManager) GetProvenance() in_toto.Statement {
	return p.prov
}

func (p *KustomizeProvenanceManager) GetProvSignature() []byte {
	return p.sig
}

func generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha string, provTrace string) []intotoprov02.ProvenanceMaterial {

	materials := []intotoprov02.ProvenanceMaterial{}

	materials = append(materials, intotoprov02.ProvenanceMaterial{
		URI: appSourceRepoUrl + ".git",
		Digest: intotoprov02.DigestSet{
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
			intoMat := intotoprov02.ProvenanceMaterial{
				URI: uri,
				Digest: intotoprov02.DigestSet{
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

// generate provenance data by checking kustomization.yaml and its sub resources
// all local files and remote repos are included in `materials` of a generated provenance
func GenerateProvenance(artifactName, digest, kustomizeBase string, startTime, finishTime time.Time, recipeCmd []string) (*intoto.Statement, error) {

	subjects := []intoto.Subject{}
	subjects = append(subjects, intoto.Subject{
		Name: artifactName,
		Digest: intotoprov02.DigestSet{
			"sha256": digest,
		},
	})

	materials, err := generateMaterialsFromKustomization(kustomizeBase)
	if err != nil {
		return nil, err
	}

	// TODO: set recipe command dynamically or somthing
	entryPoint := recipeCmd[0]
	invocation := intotoprov02.ProvenanceInvocation{
		ConfigSource: intotoprov02.ConfigSource{EntryPoint: entryPoint},
		Parameters:   recipeCmd[1:],
	}
	it := &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: intotoprov02.PredicateSLSAProvenance,
			Subject:       subjects,
		},
		Predicate: intotoprov02.ProvenancePredicate{
			Metadata: &intotoprov02.ProvenanceMetadata{
				Reproducible:    true,
				BuildStartedOn:  &startTime,
				BuildFinishedOn: &finishTime,
			},

			Materials:  materials,
			Invocation: invocation,
		},
	}
	return it, nil
}

// generate a rekor entry data by signing a specified provenance with private key
// the output data contains a base64 encoded provenance and its signature.
// it can be used in `rekor-cli upload --artifact xxxxx`.
func GenerateAttestation(provPath, privKeyPath string) (*dsse.Envelope, error) {
	b, err := os.ReadFile(provPath)
	if err != nil {
		return nil, err
	}
	ecdsaPriv, _ := os.ReadFile(filepath.Clean(privKeyPath))
	pb, _ := pem.Decode(ecdsaPriv)
	pwd := os.Getenv(cosignPwdEnvKey) //GetPass(true)
	x509Encoded, err := encrypted.Decrypt(pb.Bytes, []byte(pwd))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}

	signer, err := dsse.NewEnvelopeSigner(&IntotoSigner{
		key: priv.(*ecdsa.PrivateKey),
	})
	if err != nil {
		return nil, err
	}

	envelope, err := signer.SignPayload("application/vnd.in-toto+json", b)
	if err != nil {
		return nil, err
	}

	// Now verify
	_, err = signer.Verify(envelope)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

// get a digest of artifact by checking artifact type
// when the artifact is local file --> sha256 file hash
//
//	is OCI image --> image digest
func GetDigestOfArtifact(artifactPath string) (string, error) {
	var digest string
	var err error
	if FileExists(artifactPath) {
		// if file exists, then use hash of the file
		digest, err = Sha256Hash(artifactPath)
	} else {
		// otherwise, artifactPath should be an image ref
		digest, err = GetImageDigest(artifactPath)
	}
	return digest, err
}

// overwrite `subject` in provenance with a specified artifact
func OverwriteArtifactInProvenance(provPath, overwriteArtifact string) (string, error) {
	b, err := os.ReadFile(provPath)
	if err != nil {
		return "", err
	}
	var prov *intoto.Statement
	err = json.Unmarshal(b, &prov)
	if err != nil {
		return "", err
	}
	digest, err := GetDigestOfArtifact(overwriteArtifact)
	if err != nil {
		return "", err
	}
	subj := intoto.Subject{
		Name: overwriteArtifact,
		Digest: intotoprov02.DigestSet{
			"sha256": digest,
		},
	}
	if len(prov.Subject) == 0 {
		prov.Subject = append(prov.Subject, subj)
	} else {
		prov.Subject[0] = subj
	}
	provBytes, _ := json.Marshal(prov)
	dir, err := os.MkdirTemp("", "newprov")
	if err != nil {
		return "", err
	}
	basename := filepath.Base(provPath)
	newProvPath := filepath.Join(dir, basename)
	err = os.WriteFile(newProvPath, provBytes, 0644)
	if err != nil {
		return "", err
	}
	return newProvPath, nil
}

func generateMaterialsFromKustomization(kustomizeBase string) ([]intotoprov02.ProvenanceMaterial, error) {
	var resources []*KustomizationResource
	var err error
	repoURL, repoRevision, kustPath, err := checkRepoInfoOfKustomizeBase(kustomizeBase)
	if err == nil {
		// a repository in local filesystem
		resources, err = LoadKustomization(kustPath, "", repoURL, repoRevision, true)
	} else {
		// pure kustomization.yaml which is not in repository
		resources, err = LoadKustomization(kustomizeBase, "", "", "", false)
	}
	if err != nil {
		return nil, err
	}
	materials := []intotoprov02.ProvenanceMaterial{}
	for _, r := range resources {
		m := resourceToMaterial(r)
		if m == nil {
			continue
		}
		materials = append(materials, *m)
	}
	return materials, nil
}

func checkRepoInfoOfKustomizeBase(kustomizeBase string) (string, string, string, error) {
	url, err := GitExec(kustomizeBase, "config", "--get", "remote.origin.url")
	if err != nil {
		return "", "", "", errors.Wrap(err, "failed to get remote.origin.url")
	}
	url = strings.TrimSuffix(url, "\n")
	revision, err := GitExec(kustomizeBase, "rev-parse", "HEAD")
	if err != nil {
		return "", "", "", errors.Wrap(err, "failed to get revision HEAD")
	}
	revision = strings.TrimSuffix(revision, "\n")
	absKustBase, err := filepath.Abs(kustomizeBase)
	if err != nil {
		return "", "", "", errors.Wrap(err, "failed to get absolute path of kustomize base dir")
	}
	rootDirInRepo, err := GitExec(kustomizeBase, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", "", errors.Wrap(err, "failed to get root directory of repository")
	}
	rootDirInRepo = strings.TrimSuffix(rootDirInRepo, "\n")
	relativePath := strings.TrimPrefix(absKustBase, rootDirInRepo)
	relativePath = strings.TrimPrefix(relativePath, "/")
	return url, revision, relativePath, nil
}

func resourceToMaterial(kr *KustomizationResource) *intotoprov02.ProvenanceMaterial {
	if kr.File == nil && kr.GitRepo == nil {
		return nil
	} else if kr.File != nil {
		m := &intotoprov02.ProvenanceMaterial{
			URI: kr.File.Name,
			Digest: intotoprov02.DigestSet{
				"hash": kr.File.Hash,
			},
		}
		return m
	} else if kr.GitRepo != nil {
		m := &intotoprov02.ProvenanceMaterial{
			URI: kr.GitRepo.URL,
			Digest: intotoprov02.DigestSet{
				"commit":   kr.GitRepo.CommitID,
				"revision": kr.GitRepo.Revision,
				"path":     kr.GitRepo.Path,
			},
		}
		return m
	}
	return nil
}

// returns image digest
func GetImageDigest(resBundleRef string) (string, error) {
	ref, err := name.ParseReference(resBundleRef)
	if err != nil {
		return "", err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	hash, err := img.Digest()
	if err != nil {
		return "", err
	}
	hashValue := strings.TrimPrefix(hash.String(), "sha256:")
	return hashValue, nil
}

type IntotoSigner struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// sign a provenance data
func (it *IntotoSigner) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	sig, err := it.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// sverify a provenance data and its signature
func (it *IntotoSigner) Verify(data, sig []byte) error {
	h := sha256.Sum256(data)
	ok := ecdsa.VerifyASN1(&it.key.PublicKey, h[:], sig)
	if ok {
		return nil
	}
	return errors.New("invalid signature")
}

func (es *IntotoSigner) KeyID() (string, error) {
	return es.keyID, nil
}

func (es *IntotoSigner) Public() crypto.PublicKey {
	return es.key.Public()
}
