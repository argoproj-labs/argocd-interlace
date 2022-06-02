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

package utils

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	argoio "github.com/argoproj/argo-cd/v2/util/io"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	MANIFEST_FILE_NAME        = "manifest.yaml"
	MANIFEST_DIR              = "manifest-bundles"
	SIGNED_MANIFEST_FILE_NAME = "manifest.signed"
	PROVENANCE_FILE_NAME      = "provenance.yaml"
	ATTESTATION_FILE_NAME     = "attestation.json"
	TMP_DIR                   = "/tmp/output"
	PRIVATE_KEY_PATH          = "/etc/keys/cosign.key"
	KEYRING_PUB_KEY_PATH      = "/etc/keys/pubring.gpg"
	SIG_ANNOTATION_NAME       = "cosign.sigstore.dev/signature"
	MSG_ANNOTATION_NAME       = "cosign.sigstore.dev/message"
	RETRY_ATTEMPTS            = 10
)

const patchType = "application/merge-patch+json"

//GetClient returns a kubernetes client
func GetClient(configpath string) (*kubernetes.Clientset, *rest.Config, error) {

	if configpath == "" {
		log.Debug("Using Incluster configuration")

		config, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("Error occured while reading incluster kubeconfig %s", err.Error())
			return nil, nil, err
		}
		clientset, _ := kubernetes.NewForConfig(config)
		return clientset, config, nil
	}

	config, err := clientcmd.BuildConfigFromFlags("", configpath)
	if err != nil {
		log.Errorf("Error occured while reading kubeconfig %s ", err.Error())
		return nil, nil, err
	}
	clientset, _ := kubernetes.NewForConfig(config)
	return clientset, config, nil
}

func WriteToFile(str, dirPath, filename string) error {

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			log.Errorf("Error occured while creating a dir %s ", err.Error())
			return err
		}
	}

	absFilePath := filepath.Join(dirPath, filename)

	f, err := os.Create(absFilePath)
	if err != nil {
		log.Errorf("Error occured while opening file %s ", err.Error())
		return err
	}

	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		log.Errorf("Error occured while writing to file %s ", err.Error())
		return err
	}

	return nil

}

func QueryAPI(url, requestType, bearerToken string, data map[string]interface{}) (string, error) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	bearer := ""
	if bearerToken != "" {
		bearer = "Bearer " + bearerToken
	}

	var dataJson []byte
	if data != nil {
		dataJson, _ = json.Marshal(data)
	} else {
		dataJson = nil
	}
	req, err := http.NewRequest(requestType, url, bytes.NewBuffer(dataJson))
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	if bearer != "" {
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error %s", err.Error())
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	return string([]byte(body)), nil
}

func RetriveDesiredManifest(appName string) ([]string, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
	}

	baseUrl := interlaceConfig.ArgocdApiBaseUrl
	manifestsAPIURL := fmt.Sprintf("%s/api/v1/applications/%s/manifests", baseUrl, appName)

	token, err := GetArgoCDUserToken(interlaceConfig.ArgocdApiBaseUrl, interlaceConfig.ArgocdUser, interlaceConfig.ArgocdUserPwd)
	if err != nil {
		return nil, errors.Wrap(err, "error when getting argocd user token")
	}
	manifestsResponse, err := QueryAPI(manifestsAPIURL, "GET", token, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error occured while querying argocd REST API")
	}

	var respMap map[string]interface{}
	err = json.Unmarshal([]byte(manifestsResponse), &respMap)
	if err != nil {
		return nil, errors.Wrap(err, "error occured while marshaling the manifest API response")
	}

	var manifestsIf interface{}
	var manifestsIfList []interface{}
	var manifests []string
	var ok bool
	if manifestsIf, ok = respMap["manifests"]; !ok {
		return nil, errors.New("`manifests` is not found in the manifest API response")
	}
	if manifestsIfList, ok = manifestsIf.([]interface{}); !ok {
		return nil, fmt.Errorf("expect `[]interface{}` for manifests, but got `%T`", manifestsIf)
	}
	for _, manifestIf := range manifestsIfList {
		if tmpMnf, ok := manifestIf.(string); !ok {
			log.Errorf("expect `string` in the manifest list, but got `%T`", manifestIf)
		} else {
			manifests = append(manifests, tmpMnf)
		}
	}
	return manifests, nil
}

func GetArgoCDUserToken(apiBaseURL, argocdUser, argocdUserPass string) (string, error) {
	sessionURL := fmt.Sprintf("%s/api/v1/session", apiBaseURL)
	input := map[string]interface{}{
		"username": argocdUser,
		"password": argocdUserPass,
	}
	sessiondata, err := QueryAPI(sessionURL, "POST", "", input)
	if err != nil {
		return "", err
	}
	log.Debugf("sessiondata from argocd api: %s", string(sessiondata))
	var output map[string]interface{}
	err = json.Unmarshal([]byte(sessiondata), &output)
	if err != nil {
		return "", err
	}
	sessionTokenIf, ok := output["token"]
	if !ok {
		return "", errors.New("argocd user token is not found in the response from the session api")
	}
	sessionToken, ok := sessionTokenIf.(string)
	if !ok {
		return "", fmt.Errorf("the token returned from the session api was not a string, but %T", sessionTokenIf)
	}
	return sessionToken, nil
}

func PatchResource(appName, namespace, resourceName, group, version, kind string, patchBytes []byte) error {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		return errors.Wrap(err, "failed to load interlace config")
	}
	baseUrl := interlaceConfig.ArgocdApiBaseUrl
	opt := &apiclient.ClientOptions{
		ServerAddr: baseUrl,
		Insecure:   true,
		GRPCWeb:    true,
	}
	client, err := apiclient.NewClient(opt)
	if err != nil {
		return errors.Wrap(err, "failed to initialize argocd client set")
	}
	conn, appClient, err := client.NewApplicationClient()
	if err != nil {
		return errors.Wrap(err, "failed to initialize argocd application client")
	}
	defer argoio.Close(conn)

	resourcePatchRequest := &application.ApplicationResourcePatchRequest{
		Name:         &appName,
		Namespace:    namespace,
		ResourceName: resourceName,
		Group:        group,
		Version:      version,
		Kind:         kind,
		Patch:        string(patchBytes),
		PatchType:    patchType,
	}
	resourcePatchResp, err := appClient.PatchResource(context.Background(), resourcePatchRequest)
	if err != nil {
		return errors.Wrap(err, "failed to patch resource")
	}
	log.Debugf("patch resource response: %s", resourcePatchResp.Manifest)
	return nil
}

func FileExist(fpath string) bool {
	if _, err := os.Stat(fpath); err == nil {
		return true
	}
	return false
}

func ComputeHash(filePath string) (string, error) {
	if FileExist(filePath) {
		f, err := os.Open(filePath)
		if err != nil {
			log.Info("Error in opening file !")
			return "", err
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Info("Error in copying file !")
			return "", err
		}

		sum := h.Sum(nil)
		hashstring := fmt.Sprintf("%x", sum)
		return hashstring, nil
	}
	return "", fmt.Errorf("File not found ")
}

func CmdExec(baseCmd, dir string, args ...string) (string, error) {
	cmd := exec.Command(baseCmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if dir != "" {
		cmd.Dir = dir
	}
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, stderr.String())
	}
	out := stdout.String()
	return out, nil
}
