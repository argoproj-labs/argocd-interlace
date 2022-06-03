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
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/sirupsen/logrus"
)

const (
	configDir                        = "/etc/config"
	argocdServerName                 = "argocd-server"
	openshiftGitopsServerName        = "openshift-gitops-server"
	argocdUserSecretName             = "argocd-initial-admin-secret"
	openshiftGitopsUserSecretName    = "openshift-gitops-cluster"
	argocdUserSecretDataKey          = "password"
	openshiftGitopsUserSecretDataKey = "admin.password"
	defaultUsername                  = "admin"
	placeholderText                  = "REPLACE THIS"
)

type InterlaceConfig struct {
	LogLevel                 string
	ManifestStorageType      string
	ArgocdNamespace          string
	ArgocdInterlaceNamespace string
	ArgocdApiBaseUrl         string
	ArgocdServer             string
	ArgocdApiToken           string
	ArgocdAPIUser            string
	ArgocdAPIPass            string
	RekorServer              string
	RekorTmpDir              string
	ManifestAppSetMode       string
	ManifestArgocdProj       string
	ManifestSuffix           string
	SourceMaterialHashList   string
	SourceMaterialSignature  string
	AlwaysGenerateProv       bool
	SignatureResourceLabel   string
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
		return nil, errors.New("MANIFEST_STORAGE_TYPE is empty, please specify in configuration !")
	}

	argocdInterlaceNamespace := os.Getenv("ARGOCD_INTERLACE_NAMESPACE")
	if argocdInterlaceNamespace == "" {
		return nil, errors.New("ARGOCD_INTERLACE_NAMESPACE is empty, please specify in configuration !")
	}

	sourceHashList := os.Getenv("SOURCE_MATERIAL_HASH_LIST")

	if sourceHashList == "" {
		return nil, errors.New("SOURCE_MATERIAL_HASH_LIST is empty, please specify in configuration !")
	}

	sourceHashSignature := os.Getenv("SOURCE_MATERIAL_SIGNATURE")

	if sourceHashSignature == "" {
		return nil, errors.New("SOURCE_MATERIAL_SIGNATURE is empty, please specify in configuration !")
	}

	alwaysGenerateProv := os.Getenv("ALWAYS_GENERATE_PROV")

	if alwaysGenerateProv == "" {
		return nil, errors.New("ALWAYS_GENERATE_PROV is empty, please specify in configuration !")
	}
	alwayGenProv, _ := strconv.ParseBool(alwaysGenerateProv)

	signRscLabel := os.Getenv("SIGNATURE_RSC_LABEL")

	if signRscLabel == "" {
		return nil, errors.New("SIGNATURE_RSC_LABEL is empty, please specify in configuration !")
	}

	config := &InterlaceConfig{
		LogLevel:                 logLevel,
		ManifestStorageType:      manifestStorageType,
		ArgocdInterlaceNamespace: argocdInterlaceNamespace,
		SourceMaterialHashList:   sourceHashList,
		SourceMaterialSignature:  sourceHashSignature,
		AlwaysGenerateProv:       alwayGenProv,
		SignatureResourceLabel:   signRscLabel,
	}

	if manifestStorageType == "annotation" {
		rekorServer := os.Getenv("REKOR_SERVER")
		if rekorServer == "" {
			return nil, errors.New("REKOR_SERVER is empty, please specify in configuration !")
		}
		config.RekorServer = rekorServer

		config.RekorTmpDir = os.Getenv("REKORTMPDIR")

		return config, nil

	}

	return nil, fmt.Errorf("unsupported storage type %s", manifestStorageType)

}

func (c *InterlaceConfig) loadArgoCDNamespaceConfig() string {
	nsBytes, err := ioutil.ReadFile(filepath.Join(configDir, "argocdNamespace"))
	if err != nil {
		log.Errorf("failed to load argocd namespace config: %s", err.Error())
		return ""
	}
	return strings.TrimSuffix(string(nsBytes), "\n")
}

func (c *InterlaceConfig) loadArgoCDAPIUsernameConfig() string {
	userBytes, err := ioutil.ReadFile(filepath.Join(configDir, "argocdAPIUsername"))
	if err != nil {
		log.Errorf("failed to load argocd api username config: %s", err.Error())
		return ""
	}
	return strings.TrimSuffix(string(userBytes), "\n")
}

func (c *InterlaceConfig) loadArgoCDAPIPasswordConfig() string {
	passBytes, err := ioutil.ReadFile(filepath.Join(configDir, "argocdAPIPassword"))
	if err != nil {
		log.Errorf("failed to load argocd api password config: %s", err.Error())
		return ""
	}
	return strings.TrimSuffix(string(passBytes), "\n")
}

func (c *InterlaceConfig) checkAPIConnection() string {
	url := fmt.Sprintf("https://%s.%s.svc.cluster.local", argocdServerName, c.ArgocdNamespace)
	if ok := ping(url); ok {
		return url
	}
	url = fmt.Sprintf("https://%s.%s.svc.cluster.local", openshiftGitopsServerName, c.ArgocdNamespace)
	if ok := ping(url); ok {
		return url
	}
	return ""
}

func (c *InterlaceConfig) getArgoCDAPIUserInfoFromSecret() (string, string, error) {
	clientset, _, err := utils.GetK8sClient("")
	if err != nil {
		return "", "", errors.Wrap(err, "failed to get kubernetes client")
	}
	argoSecretList, err := clientset.CoreV1().Secrets(c.ArgocdNamespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", "", errors.Wrap(err, "failed to list argocd secret")
	}
	found := false
	var userSecret corev1.Secret
	for _, s := range argoSecretList.Items {
		secretName := s.GetName()
		if secretName == argocdUserSecretName || secretName == openshiftGitopsUserSecretName {
			userSecret = s
			found = true
			break
		}
	}
	if !found {
		return "", "", fmt.Errorf("failed to find the argocd user secret in %s namespace: either `%s` or `%s` must be there", c.ArgocdNamespace, argocdUserSecretName, openshiftGitopsUserSecretName)
	}
	username := defaultUsername
	data := userSecret.Data
	if passwordBytes, ok := data[argocdUserSecretDataKey]; ok {
		return username, string(passwordBytes), nil
	} else if passwordBytes, ok = data[openshiftGitopsUserSecretDataKey]; ok {
		return username, string(passwordBytes), nil
	} else {
		return "", "", fmt.Errorf("failed to find argocd user password in the secret `%s`", userSecret.GetName())
	}
}

func (c *InterlaceConfig) CheckReadiness() (bool, error) {
	var err error
	ns := c.loadArgoCDNamespaceConfig()
	if ns == "" || ns == placeholderText {
		return false, fmt.Errorf("`ARGOCD_NAMESPACE` is \"%s\" currently, please set this parameter", ns)
	}
	user := c.loadArgoCDAPIUsernameConfig()
	pass := c.loadArgoCDAPIPasswordConfig()
	isUserEmpty := (user == "" || user == placeholderText)
	isPassEmpty := (pass == "" || pass == placeholderText)
	if isUserEmpty && isPassEmpty {
		user, pass, err = c.getArgoCDAPIUserInfoFromSecret()
		if err != nil {
			return false, errors.Wrap(err, "failed to get argocd api username and passowrd")
		}
	}
	c.ArgocdNamespace = ns
	c.ArgocdAPIUser = user
	c.ArgocdAPIPass = pass
	apiURL := c.checkAPIConnection()
	if apiURL == "" {
		return false, fmt.Errorf("failed to connect to ArgoCD API in %s namespace", ns)
	}
	c.ArgocdApiBaseUrl = apiURL
	return true, nil
}

func ping(baseURL string) bool {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	url := fmt.Sprintf("%s/api/version", baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Errorf("failed to create a new http request for ping; %s", err.Error())
		return false
	}

	client := &http.Client{}
	_, err = client.Do(req)
	ok := err == nil
	return ok
}
