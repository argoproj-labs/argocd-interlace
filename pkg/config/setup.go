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

package config

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

type InterlaceConfig struct {
	LogLevel              string
	ManifestStorageType   string
	ArgocdNamespace       string
	ArgocdApiBaseUrl      string
	ArgocdApiToken        string
	OciImageRegistry      string
	OciImagePrefix        string
	OciImageTag           string
	RekorServer           string
	RekorTmpDir           string
	ManifestAppSetMode    string
	ManifestArgocdProj    string
	ManifestDestNamespace string
	ManifestSuffix        string
	ManifestGitUrl        string
	ManifestGitBranch     string
	ManifestGitUserId     string
	ManifestGitUserEmail  string
	ManifestGitToken      string
}

var instance *InterlaceConfig

func GetInterlaceConfig() (*InterlaceConfig, error) {
	var err error
	if instance == nil {
		instance, err = newConfig()
		if err != nil {
			log.Errorf("Error in loading config: %s", err.Error())
			return nil, err
		}
	}
	return instance, nil
}

func newConfig() (*InterlaceConfig, error) {
	logLevel := os.Getenv("ARGOCD_INTERLACE_LOG_LEVEL")

	manifestStorageType := os.Getenv("MANIFEST_STORAGE_TYPE")

	if manifestStorageType == "" {
		return nil, fmt.Errorf("MANIFEST_STORAGE_TYPE is empty, please specify in configuration !")
	}

	argocdNamespace := os.Getenv("ARGOCD_NAMESPACE")
	if argocdNamespace == "" {
		return nil, fmt.Errorf("ARGOCD_NAMESPACE is empty, please specify in configuration !")
	}

	argocdApiBaseUrl := os.Getenv("ARGOCD_API_BASE_URL")
	if argocdApiBaseUrl == "" {
		return nil, fmt.Errorf("ARGOCD_API_BASE_URL is empty, please specify in configuration !")
	}

	argocdApiToken := os.Getenv("ARGOCD_TOKEN")
	if argocdApiToken == "" {
		return nil, fmt.Errorf("ARGOCD_TOKEN is empty, please specify in configuration !")
	}

	config := &InterlaceConfig{
		LogLevel:            logLevel,
		ManifestStorageType: manifestStorageType,
		ArgocdNamespace:     argocdNamespace,
		ArgocdApiBaseUrl:    strings.TrimSuffix(argocdApiBaseUrl, "\n") + "/api/v1/applications",
		ArgocdApiToken:      strings.TrimSuffix(argocdApiToken, "\n"),
	}

	if manifestStorageType == "oci" {

		ociImageRegistry := os.Getenv("OCI_IMAGE_REGISTRY")

		if ociImageRegistry == "" {
			return nil, fmt.Errorf("OCI_IMAGE_REGISTRY is empty, please specify in configuration !")
		}

		config.OciImageRegistry = ociImageRegistry

		ociImagePrefix := os.Getenv("OCI_IMAGE_PREFIX")
		if ociImagePrefix == "" {
			return nil, fmt.Errorf("OCI_IMAGE_PREFIX is empty, please specify in configuration !")
		}
		config.OciImagePrefix = ociImagePrefix

		ociImageTag := os.Getenv("OCI_IMAGE_TAG")
		if ociImageTag == "" {
			return nil, fmt.Errorf("OCI_IMAGE_TAG is empty, please specify in configuration !")
		}
		config.OciImageTag = ociImageTag

		rekorServer := os.Getenv("REKOR_SERVER")
		if rekorServer == "" {
			return nil, fmt.Errorf("REKOR_SERVER is empty, please specify in configuration !")
		}
		config.RekorServer = rekorServer

		config.RekorTmpDir = os.Getenv("REKORTMPDIR")

		return config, nil

	} else if manifestStorageType == "git" {

		manifestAppSetMode := os.Getenv("MANIFEST_GITREPO_MODE")

		if manifestAppSetMode == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_MODE is empty, please specify in configuration !")
		}

		config.ManifestAppSetMode = manifestAppSetMode

		manifestArgocdProj := os.Getenv("MANIFEST_ARGOCD_PROJECT")

		if manifestArgocdProj == "" {
			return nil, fmt.Errorf("MANIFEST_ARGOCD_PROJECT is empty, please specify in configuration !")
		}

		config.ManifestArgocdProj = manifestArgocdProj

		manifestDestNamespace := os.Getenv("MANIFEST_DEST_NAMESPACE")

		if manifestDestNamespace == "" {
			return nil, fmt.Errorf("MANIFEST_DEST_NAMESPACE is empty, please specify in configuration !")
		}
		config.ManifestDestNamespace = manifestDestNamespace

		manifestSuffix := os.Getenv("MANIFEST_GITREPO_SUFFIX")

		if manifestSuffix == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_SUFFIX is empty, please specify in configuration !")
		}

		config.ManifestSuffix = manifestSuffix

		manifestGitUrl := os.Getenv("MANIFEST_GITREPO_URL")

		if manifestGitUrl == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_URL is empty, please specify in configuration !")
		}
		config.ManifestGitUrl = manifestGitUrl

		manifestGitBranch := os.Getenv("MANIFEST_GITREPO_BRANCH")

		if manifestGitBranch == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_BRANCH is empty, please specify in configuration !")
		}

		config.ManifestGitBranch = manifestGitBranch

		manifestGitUserId := os.Getenv("MANIFEST_GITREPO_USER")

		if manifestGitUserId == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_USER is empty, please specify in configuration !")
		}
		config.ManifestGitUserId = manifestGitUserId

		manifestGitUserEmail := os.Getenv("MANIFEST_GITREPO_USEREMAIL")

		if manifestGitUserEmail == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_USEREMAIL is empty, please specify in configuration !")
		}
		config.ManifestGitUserEmail = manifestGitUserEmail

		manifestGitToken := os.Getenv("MANIFEST_GITREPO_TOKEN")

		if manifestGitToken == "" {
			return nil, fmt.Errorf("MANIFEST_GITREPO_TOKEN is empty, please specify in configuration !")
		}
		config.ManifestGitToken = manifestGitToken

		return config, nil

	}

	return nil, fmt.Errorf("Unsupported storage type %s", manifestStorageType)

}
