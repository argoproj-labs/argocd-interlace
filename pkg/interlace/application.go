//
// Copyright 2020 IBM Corporation
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

package interlace

import (
	"fmt"
	"path/filepath"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func createApplication(appName, appPath, server, sourcePath string) (string, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return "", nil
	}

	repoUrl := interlaceConfig.ManifestGitUrl
	targetRevision := interlaceConfig.ManifestGitBranch

	argocdProj := interlaceConfig.ManifestArgocdProj       //"default"
	destNamespace := interlaceConfig.ManifestDestNamespace //"default"

	suffix := interlaceConfig.ManifestSuffix
	argocdNamespace := interlaceConfig.ArgocdNamespace

	manifestSigAppName := appName + suffix

	//path := filepath.Join(appName, appPath)

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      manifestSigAppName,
			"namespace": argocdNamespace,
		},
		"spec": map[string]interface{}{
			"destination": map[string]interface{}{
				"namespace": destNamespace,
				"server":    server,
			},
			"source": map[string]interface{}{
				"path":           sourcePath,
				"repoURL":        repoUrl,
				"targetRevision": targetRevision,
			},
			"syncPolicy": map[string]interface{}{
				"automated": map[string]interface{}{
					"prune":    true,
					"selfHeal": true,
				},
			},
			"project": argocdProj,
		},
	}

	argoCdBaseUrl := interlaceConfig.ArgocdApiBaseUrl

	desiredUrl := fmt.Sprintf("%s?upsert=true&validate=true", argoCdBaseUrl)

	argoCdtoken := interlaceConfig.ArgocdApiToken

	response, err := utils.QueryAPI(desiredUrl, "POST", argoCdtoken, data)

	if err != nil {
		log.Errorf("Error in querying ArgoCD api: %s", err.Error())
		return "", err
	}

	return response, nil
}

func updateApplication(appName, appPath, server string) (string, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return "", nil
	}
	repoUrl := interlaceConfig.ManifestGitUrl
	targetRevision := interlaceConfig.ManifestGitBranch

	argocdProj := interlaceConfig.ManifestArgocdProj       //"default"
	destNamespace := interlaceConfig.ManifestDestNamespace //"default"

	suffix := interlaceConfig.ManifestSuffix
	argocdNamespace := interlaceConfig.ArgocdNamespace
	manifestSigAppName := appName + suffix

	path := filepath.Join(appName, appPath)

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      manifestSigAppName,
			"namespace": argocdNamespace,
		},
		"spec": map[string]interface{}{
			"destination": map[string]interface{}{
				"namespace": destNamespace,
				"server":    server,
			},
			"source": map[string]interface{}{
				"path":           path,
				"repoURL":        repoUrl,
				"targetRevision": targetRevision,
			},
			"syncPolicy": map[string]interface{}{
				"automated": map[string]interface{}{
					"prune":    true,
					"selfHeal": true,
				},
			},
			"project": argocdProj,
		},
	}
	argoCdBaseUrl := interlaceConfig.ArgocdApiBaseUrl

	desiredUrl := fmt.Sprintf("%s/%s", argoCdBaseUrl, manifestSigAppName)
	argoCdtoken := interlaceConfig.ArgocdApiToken
	response, err := utils.QueryAPI(desiredUrl, "POST", argoCdtoken, data)
	if err != nil {
		return "", err
	}

	return response, nil
}

func listApplication(appName string) (string, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return "", nil
	}

	suffix := interlaceConfig.ManifestSuffix
	manifestSigAppName := appName + suffix
	argoCdBaseUrl := interlaceConfig.ArgocdApiBaseUrl

	desiredUrl := fmt.Sprintf("%s/%s", argoCdBaseUrl, manifestSigAppName)

	argoCdtoken := interlaceConfig.ArgocdApiToken
	response, err := utils.QueryAPI(desiredUrl, "GET", argoCdtoken, nil)

	if err != nil {
		return "", err
	}
	return response, nil
}
