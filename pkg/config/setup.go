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
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type InterlaceConfig struct {
	LogLevel                string
	ManifestStorageType     string
	ArgocdNamespace         string
	ArgocdApiBaseUrl        string
	ArgocdServer            string
	ArgocdApiToken          string
	ArgocdPwd               string
	RekorServer             string
	RekorTmpDir             string
	ManifestAppSetMode      string
	ManifestArgocdProj      string
	ManifestSuffix          string
	SourceMaterialHashList  string
	SourceMaterialSignature string
	AlwaysGenerateProv      bool
	SignatureResourceLabel  string
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

	argocdServer := strings.ReplaceAll(argocdApiBaseUrl, "https://", "")

	argocdApiToken := os.Getenv("ARGOCD_TOKEN")
	if argocdApiToken == "" {
		return nil, fmt.Errorf("ARGOCD_TOKEN is empty, please specify in configuration !")
	}
	argocdPwd := os.Getenv("ARGOCD_PWD")
	if argocdPwd == "" {
		return nil, fmt.Errorf("ARGOCD_PWD is empty, please specify in configuration !")
	}

	sourceHashList := os.Getenv("SOURCE_MATERIAL_HASH_LIST")

	if sourceHashList == "" {
		return nil, fmt.Errorf("SOURCE_MATERIAL_HASH_LIST is empty, please specify in configuration !")
	}

	sourceHashSignature := os.Getenv("SOURCE_MATERIAL_SIGNATURE")

	if sourceHashSignature == "" {
		return nil, fmt.Errorf("SOURCE_MATERIAL_SIGNATURE is empty, please specify in configuration !")
	}

	alwaysGenerateProv := os.Getenv("ALWAYS_GENERATE_PROV")

	if alwaysGenerateProv == "" {
		return nil, fmt.Errorf("ALWAYS_GENERATE_PROV is empty, please specify in configuration !")
	}
	alwayGenProv, _ := strconv.ParseBool(alwaysGenerateProv)

	signRscLabel := os.Getenv("SIGNATURE_RSC_LABEL")

	if signRscLabel == "" {
		return nil, fmt.Errorf("SIGNATURE_RSC_LABEL is empty, please specify in configuration !")
	}

	config := &InterlaceConfig{
		LogLevel:                logLevel,
		ManifestStorageType:     manifestStorageType,
		ArgocdNamespace:         argocdNamespace,
		ArgocdApiBaseUrl:        strings.TrimSuffix(argocdApiBaseUrl, "\n") + "/api/v1/applications",
		ArgocdServer:            strings.TrimSuffix(argocdServer, "\n"),
		ArgocdApiToken:          strings.TrimSuffix(argocdApiToken, "\n"),
		ArgocdPwd:               strings.TrimSuffix(argocdPwd, "\n"),
		SourceMaterialHashList:  sourceHashList,
		SourceMaterialSignature: sourceHashSignature,
		AlwaysGenerateProv:      alwayGenProv,
		SignatureResourceLabel:  signRscLabel,
	}

	if manifestStorageType == "annotation" {
		rekorServer := os.Getenv("REKOR_SERVER")
		if rekorServer == "" {
			return nil, fmt.Errorf("REKOR_SERVER is empty, please specify in configuration !")
		}
		config.RekorServer = rekorServer

		config.RekorTmpDir = os.Getenv("REKORTMPDIR")

		return config, nil

	}

	return nil, fmt.Errorf("Unsupported storage type %s", manifestStorageType)

}
