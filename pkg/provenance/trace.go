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

package provenance

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/IBM/argocd-interlace/pkg/utils"
	k8sutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TraceProvenance(repoUrl, previousCommitSha, currentCommitSha string) {

	gitToken := GetRepoCredentials(repoUrl)

	orgName, repoName := getRepoInfo(repoUrl)

	getDiff(previousCommitSha, currentCommitSha, orgName, repoName, gitToken)

	// generate dif for top repo (current vs remote)
	// get list of remote base repo + commits (current vs remote)

}

func GitLatestCommitSha(repoUrl string, branch string) string {

	gitToken := GetRepoCredentials(repoUrl)

	orgName, repoName := getRepoInfo(repoUrl)

	desiredUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s",
		orgName, repoName, branch)

	response, err := utils.QueryAPI(desiredUrl, "GET", gitToken, nil)

	if err != nil {
		log.Errorf("Error occured while query github %s ", err.Error())
		return ""
	}

	sha := gjson.Get(response, "sha")
	log.Info("Latest revision ", sha)
	return sha.String()
}

func getRepoInfo(repoUrl string) (string, string) {
	tokens := strings.Split(strings.TrimSuffix(repoUrl, "/"), "/")

	orgName := tokens[3]
	repoName := tokens[4]

	log.Info(orgName)
	log.Info(repoName)
	return orgName, repoName
}
func getDiff(previousCommitSha, currentCommitSha, orgName, repoName, gitToken string) {

	log.Info("Getting diff between two commits")

	desiredUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/compare/%s...%s",
		orgName, repoName, previousCommitSha, currentCommitSha)

	response, err := utils.QueryAPI(desiredUrl, "GET", gitToken, nil)

	if err != nil {
		log.Errorf("Error occured while query github %s ", err.Error())
	}

	files := gjson.Get(response, "files")

	for _, item := range files.Array() {

		filename := gjson.Get(item.String(), "filename").String()
		sha := gjson.Get(item.String(), "sha").String()
		log.Info("filename ", filename, "  sha ", sha)
	}
}

func GetRepoCredentials(repoUrl string) string {

	_, cfg, err := utils.GetClient("")

	if err != nil {
		log.Errorf("Error occured while reading incluster kubeconfig %s", err.Error())
		return ""
	}

	k8sutil.SetKubeConfig(cfg)

	apiVersion := "v1"
	kind := "ConfigMap"
	namespace := "argocd"
	name := "argocd-cm"

	argoConfigMapObj, err := k8sutil.GetResource(apiVersion, kind, namespace, name)

	if err != nil {
		log.Errorf("Error occured while retriving ConfigMap from cluster %s", err.Error())
		return ""
	}

	argoConfigMap, err := getConfiMapFromObj(argoConfigMapObj)
	if err != nil {
		log.Errorf("Error occured while retriving ConfigMap %s", err.Error())
		return ""
	}

	repositories := argoConfigMap.Data["repositories"]
	found := false
	secretName := ""
	for _, line := range strings.Split(strings.TrimSuffix(repositories, "\n"), "\n") {

		data := strings.Split(strings.TrimSuffix(strings.TrimSpace(line), ":"), ":")
		if data[0] == "url" {
			url := strings.TrimSpace(data[1] + ":" + data[2])
			if url == repoUrl {
				found = true
			}
		}
		if data[0] == "name" {
			secretName = strings.TrimSpace(data[1])
		}
	}

	if found {

		kind = "Secret"

		argoSecretObj, err := k8sutil.GetResource(apiVersion, kind, namespace, secretName)
		if err != nil {
			log.Errorf("Error in getting  resource secret object: %s", err.Error())
			return ""
		}

		argoSecret, err := getConfiMapFromObj(argoSecretObj)
		if err != nil {
			log.Errorf("Error in getting  secret object: %s", err.Error())
			return ""
		}

		gitToken, err := base64.StdEncoding.DecodeString(string(argoSecret.Data["password"]))
		if err != nil {
			log.Errorf("Error in decoding password from secret object: %s", err.Error())
			return ""
		}
		log.Info("Found credentials for target git repo: ", repoUrl)
		return string(gitToken)
	}
	return ""
}

func getConfiMapFromObj(obj *unstructured.Unstructured) (*corev1.ConfigMap, error) {

	var cm corev1.ConfigMap
	objBytes, _ := json.Marshal(obj.Object)
	err := json.Unmarshal(objBytes, &cm)
	if err != nil {
		return nil, fmt.Errorf("error in converting object to ConfigMap; %s", err.Error())
	}

	return &cm, nil
}
