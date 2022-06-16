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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance/attestation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/pkg/errors"
	kustbuildutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/manifestbuild/kustomize"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	// package golang.org/x/crypto/openpgp is deprecated: this package is unmaintained except for security fixes.
	// New applications should consider a more focused, modern alternative to OpenPGP for their specific task.
	// If you are required to interoperate with OpenPGP systems and need a maintained package, consider a community fork.
	// See https://golang.org/issue/44226.
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

func NewProvenanceManager(appData application.ApplicationData) (*KustomizeProvenanceManager, error) {
	return &KustomizeProvenanceManager{
		appData: appData,
	}, nil
}

func (p *KustomizeProvenanceManager) GenerateProvenance(target, targetDigest string, uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error {
	appName := p.appData.AppName
	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl
	appSourceRevision := p.appData.AppSourceRevision
	appSourceCommitSha := p.appData.AppSourceCommitSha

	interlaceConfig, _ := config.GetInterlaceConfig()
	appDirPath := filepath.Join(interlaceConfig.WorkspaceDir, appName, appPath)

	manifestFile := filepath.Join(appDirPath, config.MANIFEST_FILE_NAME)
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
	if err != nil {
		log.Errorf("error when marshaling provenance:  %s", err.Error())
		return err
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

	entryPoint := "kustomize"
	invocation := intotoprov02.ProvenanceInvocation{
		ConfigSource: intotoprov02.ConfigSource{EntryPoint: entryPoint},
		Parameters:   []string{"build", baseDir},
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
		log.Errorf("Error in marshaling attestation:  %s", err.Error())
		return err
	}

	err = utils.WriteToFile(string(b), appDirPath, config.PROVENANCE_FILE_NAME)
	if err != nil {
		log.Errorf("Error in writing provenance to a file:  %s", err.Error())
		return err
	}

	provSig, provRef, err := attestation.GenerateSignedAttestation(it, appName, appDirPath, uploadTLog)
	if err != nil {
		log.Errorf("Error in generating signed attestation:  %s", err.Error())
		return err
	}
	if provSig != nil {
		p.sig = provSig
	}
	if provRef != nil {
		p.ref = *provRef
	}

	return nil
}

func (p *KustomizeProvenanceManager) VerifySourceMaterial() (bool, error) {
	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("error when getting interlace config:  %s", err.Error())
		return false, err
	}

	host, orgRepo, path, gitRef, gitSuff := ParseGitUrl(appSourceRepoUrl)

	log.Info("appSourceRepoUrl ", appSourceRepoUrl)

	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff

	log.Info("url:", url)

	r, err := GetTopGitRepo(url)
	if err != nil {
		log.Errorf("Error git clone:  %s", err.Error())
		return false, err
	}

	baseDir := filepath.Join(r.RootDir, appPath)

	keyPath := config.SourceMaterialVerifyKeyPath
	pubkeyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return false, errors.Wrap(err, "failed to read public key file")
	}
	// if verification key is empty, skip source material verification
	if string(pubkeyBytes) == "" {
		log.Warnf("verification key is empty, so skip source material verification")
		return false, nil
	}

	srcMatPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialHashList)
	srcMatSigPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialSignature)

	verification_target, err := os.Open(srcMatPath)
	if err != nil {
		log.Errorf("error when opening source material digest file:  %s", err.Error())
		return false, err
	}
	signature, err := os.Open(srcMatSigPath)
	if err != nil {
		log.Errorf("error when opening source material signature file:  %s", err.Error())
		return false, err
	}
	flag, _, _, _, _ := verifySignature(keyPath, verification_target, signature)

	hashCompareSuccess := false
	if flag {
		hashCompareSuccess, err = compareHash(srcMatPath, baseDir)
		if err != nil {
			return hashCompareSuccess, err
		}
		return hashCompareSuccess, nil
	}

	return flag, nil
}

func (p *KustomizeProvenanceManager) GetProvenance() in_toto.Statement {
	return p.prov
}

func (p *KustomizeProvenanceManager) GetProvSignature() []byte {
	return p.sig
}

func verifySignature(keyPath string, msg, sig *os.File) (bool, string, *Signer, []byte, error) {

	if keyRing, err := LoadPublicKey(keyPath); err != nil {
		return false, "Error when loading key ring", nil, nil, err
	} else if signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msg, sig, nil); signer == nil {
		if err != nil {
			log.Error("Signature verification error:", err.Error())
		}
		return false, "Signed by unauthrized subject (signer is not in public key), or invalid format signature", nil, nil, nil
	} else {
		idt := GetFirstIdentity(signer)
		fingerprint := ""
		if signer.PrimaryKey != nil {
			fingerprint = fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
		}
		return true, "", NewSignerFromUserId(idt.UserId), []byte(fingerprint), nil
	}
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}

type Signer struct {
	Email              string `json:"email,omitempty"`
	Name               string `json:"name,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	Fingerprint        []byte `json:"finerprint"`
}

func NewSignerFromUserId(uid *packet.UserId) *Signer {
	return &Signer{
		Email:   uid.Email,
		Name:    uid.Name,
		Comment: uid.Comment,
	}
}

func LoadPublicKey(keyPath string) (openpgp.EntityList, error) {
	var keyRingReader io.Reader
	var err error

	keyRingReader, err = os.Open(filepath.Clean(keyPath))
	if err != nil {
		return nil, errors.Wrap(err, "failed to read public key stream")
	}

	entities := []*openpgp.Entity{}
	var tmpList openpgp.EntityList
	var err1, err2 error
	// try loading it as a non-armored public key
	tmpList, err1 = openpgp.ReadKeyRing(keyRingReader)
	if err1 != nil {
		// keyRingReader is a stream, so it must be re-loaded after first trial
		keyRingReader, _ = os.Open(filepath.Clean(keyPath))
		// try loading it as an armored public key
		tmpList, err2 = openpgp.ReadArmoredKeyRing(keyRingReader)
	}
	// if both trial failed, return error
	if err1 != nil && err2 != nil {
		err = fmt.Errorf("failed to load public key; %s; %s", err1.Error(), err2.Error())
	} else if len(tmpList) > 0 {
		for _, tmp := range tmpList {
			entities = append(entities, tmp)
		}
	}
	return openpgp.EntityList(entities), err
}

func compareHash(sourceMaterialPath string, baseDir string) (bool, error) {
	sourceMaterial, err := ioutil.ReadFile(sourceMaterialPath)

	if err != nil {
		log.Errorf("Error in reading sourceMaterialPath:  %s", err.Error())
		return false, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(sourceMaterial)))

	for scanner.Scan() {
		l := scanner.Text()

		data := strings.Split(l, " ")
		if len(data) > 2 {
			hash := data[0]
			path := data[2]

			absPath := filepath.Join(baseDir, "/", path)
			computedFileHash, err := utils.ComputeHash(absPath)
			log.Info("file: ", path, " hash:", hash, " absPath:", absPath, " computedFileHash: ", computedFileHash)
			if err != nil {
				return false, err
			}

			if hash != computedFileHash {
				return false, nil
			}
		} else {
			continue
		}
	}
	return true, nil
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
