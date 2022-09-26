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
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance/attestation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/gitutil"
	"github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	kustbuildutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/manifestbuild/kustomize"
	log "github.com/sirupsen/logrus"
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

	provSig, provRef, err := attestation.GenerateSignedAttestation(it, appName, appDirPath, privkeyBytes, uploadTLog)
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
