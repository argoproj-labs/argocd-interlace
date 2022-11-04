//
// Copyright 2022 IBM Corporation
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

package verify

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/gitutil"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func VerifyKustomizeSourceMaterial(appPath, repoUrl string, pubkeyBytes []byte) (bool, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("error when getting interlace config:  %s", err.Error())
		return false, err
	}

	host, orgRepo, path, gitRef, gitSuff := gitutil.ParseGitUrl(repoUrl)

	log.Info("appSourceRepoUrl ", repoUrl)

	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff

	log.Info("url:", url)

	r, err := gitutil.GetTopGitRepo(url)
	if err != nil {
		return false, errors.Wrap(err, "error on git clone")
	}

	baseDir := filepath.Join(r.RootDir, appPath)

	// if verification key is empty, skip source material verification
	if string(pubkeyBytes) == "" {
		log.Warnf("verification key is empty, so skip source material verification")
		return false, nil
	}
	pubkeyFile, err := ioutil.TempFile("", "pubkey")
	if err != nil {
		return false, errors.Wrap(err, "error while creating a temp file")
	}
	defer os.Remove(pubkeyFile.Name())

	keyPath := pubkeyFile.Name()

	_, err = pubkeyFile.Write(pubkeyBytes)
	if err != nil {
		return false, errors.Wrap(err, "error while saving the public keyy as a temp file")
	}

	srcMatPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialHashList)
	srcMatSigPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialSignature)

	targetBytes, err := os.ReadFile(srcMatPath)
	if err != nil {
		return false, errors.Wrap(err, "failed to open source material digest file")
	}
	signatureBytes, err := os.ReadFile(srcMatSigPath)
	if err != nil {
		return false, errors.Wrap(err, "failed to open source material signature file")
	}

	hashCompareSuccess, err := CompareHash(srcMatPath, baseDir)
	if err != nil {
		return false, err
	}
	if !hashCompareSuccess {
		return false, errors.New("hash comparison failed")
	}

	sigType := GetSignatureTypeFromPublicKey(&keyPath)

	var sigVerified bool
	if sigType == SigTypePGP {
		sigVerified, _, _, _, err = VerifyGPGSignature(keyPath, targetBytes, signatureBytes)
	} else if sigType == SigTypeCosign {
		sigVerified, err = VerifyCosignSignature(keyPath, targetBytes, signatureBytes)
	}
	if err != nil {
		return false, errors.Wrap(err, "failed to verify the signature")
	}

	return sigVerified, nil
}

func VerifyHelmSourceMaterial(appPath, repoUrl, chart, targetRevision string) (bool, error) {
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

	log.Infof(": Helm sigstore verify was successful for the  Helm chart: %s ", chart)

	return true, nil

}
