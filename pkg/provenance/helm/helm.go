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

package helm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance/attestation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	log "github.com/sirupsen/logrus"
)

type HelmProvenanceManager struct {
	appData application.ApplicationData
	prov    in_toto.Statement
	sig     []byte
	ref     provenance.ProvenanceRef
}

const (
	ProvenanceAnnotation = "helm"
)

func NewProvenanceManager(appData application.ApplicationData) (*HelmProvenanceManager, error) {
	return &HelmProvenanceManager{
		appData: appData,
	}, nil
}

func (p *HelmProvenanceManager) GenerateProvenance(target, targetDigest string, uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error {
	appName := p.appData.AppName
	appSourceRevision := p.appData.AppSourceRevision
	appDirPath := p.appData.AppDirPath
	chart := p.appData.Chart

	entryPoint := "helm"
	helmChart := fmt.Sprintf("%s-%s.tgz", chart, appSourceRevision)
	invocation := intotoprov02.ProvenanceInvocation{
		ConfigSource: intotoprov02.ConfigSource{EntryPoint: entryPoint},
		Parameters:   []string{"install", chart, helmChart},
	}

	subjects := []in_toto.Subject{}

	targetDigest = strings.ReplaceAll(targetDigest, "sha256:", "")
	subjects = append(subjects, in_toto.Subject{Name: target,
		Digest: intotoprov02.DigestSet{
			"sha256": targetDigest,
		},
	})

	materials := p.generateMaterial()

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

func (p *HelmProvenanceManager) generateMaterial() []intotoprov02.ProvenanceMaterial {

	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl
	appSourceRevision := p.appData.AppSourceRevision
	chart := p.appData.Chart
	values := p.appData.Values
	materials := []intotoprov02.ProvenanceMaterial{}

	helmChartPath := fmt.Sprintf("%s/%s-%s.tgz", appPath, chart, appSourceRevision)
	chartHash, _ := utils.ComputeHash(helmChartPath)

	materials = append(materials, intotoprov02.ProvenanceMaterial{
		URI: appSourceRepoUrl + ".git",
		Digest: intotoprov02.DigestSet{
			"sha256hash": chartHash,
			"revision":   appSourceRevision,
			"name":       chart,
		},
	})

	materials = append(materials, intotoprov02.ProvenanceMaterial{

		Digest: intotoprov02.DigestSet{
			"material":   "values",
			"parameters": values,
		},
	})
	return materials
}

func (p *HelmProvenanceManager) VerifySourceMaterial() (bool, error) {

	appPath := p.appData.AppPath
	repoUrl := p.appData.AppSourceRepoUrl
	chart := p.appData.Chart
	targetRevision := p.appData.AppSourceRevision

	mkDirCmd := "mkdir"
	_, err := utils.CmdExec(mkDirCmd, "", appPath)
	if err != nil {
		log.Infof("mkdir returns error : %s ", err.Error())
		return false, err
	}
	helmChartUrl := fmt.Sprintf("%s/%s-%s.tgz", repoUrl, chart, targetRevision)

	chartPath := fmt.Sprintf("%s/%s-%s.tgz", appPath, chart, targetRevision)
	curlCmd := "curl"
	_, err = utils.CmdExec(curlCmd, appPath, helmChartUrl, "--output", chartPath)
	if err != nil {
		log.Infof("Retrive Helm Chart : %s ", err.Error())
		return false, err
	}

	helmChartProvUrl := fmt.Sprintf("%s/%s-%s.tgz.prov", repoUrl, chart, targetRevision)
	provPath := fmt.Sprintf("%s/%s-%s.tgz.prov", appPath, chart, targetRevision)
	_, err = utils.CmdExec(curlCmd, appPath, helmChartProvUrl, "--output", provPath)
	if err != nil {
		log.Infof("Retrive Helm Chart Prov : %s ", err.Error())
		return false, err
	}

	helmCmd := "helm"

	_, err = utils.CmdExec(helmCmd, appPath, "sigstore", "verify", chartPath)
	if err != nil {
		log.Infof("Helm-sigstore verify : %s ", err.Error())
		return false, err
	}

	log.Infof("[INFO]: Helm sigstore verify was successful for the  Helm chart: %s ", p.appData.Chart)

	return true, nil

}

func (p *HelmProvenanceManager) GetProvenance() in_toto.Statement {
	return p.prov
}

func (p *HelmProvenanceManager) GetProvSignature() []byte {
	return p.sig
}
