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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	k8sutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	ARGOCD_CONFIG_NAME    = "argocd-cm"
	ARGOCD_CONFIG_KIND    = "ConfigMap"
	ARGOCD_CONFIG_API_VER = "v1"
	ARGOCD_SECRET_KIND    = "Secret"
)

func GitLatestCommitSha(repoUrl string, branch string) string {

	gitToken := GetRepoCredentials(repoUrl)

	orgName, repoName := getRepoInfo(repoUrl)

	desiredUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s",
		orgName, repoName, branch)

	response, err := argoutil.QueryAPI(desiredUrl, "GET", gitToken, nil)

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
	orgName := ""
	repoName := ""
	if len(tokens) == 5 {
		orgName = tokens[3]
		repoName = tokens[4]
	} else if len(tokens) == 4 {
		orgName = tokens[2]
		repoName = tokens[3]
	}

	log.Info(orgName)
	log.Info(repoName)
	return orgName, repoName
}

func GetRepoCredentials(repoUrl string) string {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("error when getting interlace config %s", err.Error())
		return ""
	}

<<<<<<< Updated upstream
	_, cfg, err := utils.GetK8sClient("")

=======
	_, cfg, err := utils.GetClient("")
>>>>>>> Stashed changes
	if err != nil {
		log.Errorf("Error occured while reading incluster kubeconfig %s", err.Error())
		return ""
	}

	k8sutil.SetKubeConfig(cfg)

	apiVersion := ARGOCD_CONFIG_API_VER
	kind := ARGOCD_CONFIG_KIND
	name := ARGOCD_CONFIG_NAME
	namespace := interlaceConfig.ArgocdNamespace

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

		kind = ARGOCD_SECRET_KIND

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

const gitCmd = "git"

type GitRepoResult struct {
	RootDir  string
	URL      string
	Revision string
	CommitID string
	Path     string
}
type ConfirmedDir string

func (d ConfirmedDir) HasPrefix(path ConfirmedDir) bool {
	if path.String() == string(filepath.Separator) || path == d {
		return true
	}
	return strings.HasPrefix(
		string(d),
		string(path)+string(filepath.Separator))
}

func (d ConfirmedDir) Join(path string) string {
	return filepath.Join(string(d), path)
}

func (d ConfirmedDir) String() string {
	return string(d)
}

func NewTmpConfirmedDir() (ConfirmedDir, error) {
	n, err := ioutil.TempDir("", "kustomize-")
	if err != nil {
		return "", err
	}

	// In MacOs `ioutil.TempDir` creates a directory
	// with root in the `/var` folder, which is in turn
	// a symlinked path to `/private/var`.
	// Function `filepath.EvalSymlinks`is used to
	// resolve the real absolute path.
	deLinked, err := filepath.EvalSymlinks(n)
	return ConfirmedDir(deLinked), err
}

func GetTopGitRepo(url string) (*GitRepoResult, error) {

	log.Infof("GetTopGitRepo url : %s ", url)

	r := &GitRepoResult{}
	r.URL = url

	cDir, err := NewTmpConfirmedDir()
	if err != nil {
		log.Errorf("Error in creating temporary directory: %s", err.Error())
		return nil, err
	}

	r.RootDir = cDir.String()

	_, err = utils.CmdExec(gitCmd, r.RootDir, "init")
	if err != nil {
		log.Errorf("Error in executing git init: %s", err.Error())
		return nil, err
	}
	_, err = utils.CmdExec(gitCmd, r.RootDir, "remote", "add", "origin", r.URL)
	if err != nil {
		log.Errorf("Error in executing git remote add: %s", err.Error())
		return nil, err
	}
	rev := "HEAD"

	_, err = utils.CmdExec(gitCmd, r.RootDir, "fetch", "--depth=1", "origin", rev)
	if err != nil {
		log.Errorf("Error in executing git fetch: %s", err.Error())
		return nil, err
	}
	_, err = utils.CmdExec(gitCmd, r.RootDir, "checkout", "FETCH_HEAD")
	if err != nil {
		log.Errorf("Error in executing git checkout: %s", err.Error())
		return nil, err
	}

	commitGetOut, err := utils.CmdExec(gitCmd, r.RootDir, "rev-parse", "FETCH_HEAD")
	if err != nil {
		log.Errorf("Error in executing git rev-parse: %s", err.Error())
		return nil, err
	}
	r.CommitID = strings.TrimSuffix(commitGetOut, "\n")
	return r, nil
}

const (
	refQueryRegex = "\\?(version|ref)="
	gitSuffix     = ".git"
	gitDelimiter  = "_git/"
)

func ParseGitUrl(n string) (
	host string, orgRepo string, path string, gitRef string, gitSuff string) {

	if strings.Contains(n, gitDelimiter) {
		index := strings.Index(n, gitDelimiter)
		// Adding _git/ to host
		host = normalizeGitHostSpec(n[:index+len(gitDelimiter)])
		orgRepo = strings.Split(strings.Split(n[index+len(gitDelimiter):], "/")[0], "?")[0]
		path, gitRef = peelQuery(n[index+len(gitDelimiter)+len(orgRepo):])
		return
	}
	host, n = parseHostSpec(n)
	gitSuff = gitSuffix
	if strings.Contains(n, gitSuffix) {
		index := strings.Index(n, gitSuffix)
		orgRepo = n[0:index]
		n = n[index+len(gitSuffix):]
		path, gitRef = peelQuery(n)
		return
	}

	i := strings.Index(n, "/")
	if i < 1 {
		return "", "", "", "", ""
	}
	j := strings.Index(n[i+1:], "/")
	if j >= 0 {
		j += i + 1
		orgRepo = n[:j]
		path, gitRef = peelQuery(n[j+1:])
		return
	}
	path = ""
	orgRepo, gitRef = peelQuery(n)
	return host, orgRepo, path, gitRef, gitSuff
}

func parseHostSpec(n string) (string, string) {
	var host string
	// Start accumulating the host part.
	for _, p := range []string{
		// Order matters here.
		"git::", "gh:", "ssh://", "https://", "http://",
		"git@", "github.com:", "github.com/"} {
		if len(p) < len(n) && strings.ToLower(n[:len(p)]) == p {
			n = n[len(p):]
			host += p
		}
	}
	if host == "git@" {
		i := strings.Index(n, "/")
		if i > -1 {
			host += n[:i+1]
			n = n[i+1:]
		} else {
			i = strings.Index(n, ":")
			if i > -1 {
				host += n[:i+1]
				n = n[i+1:]
			}
		}
		return host, n
	}

	// If host is a http(s) or ssh URL, grab the domain part.
	for _, p := range []string{
		"ssh://", "https://", "http://"} {
		if strings.HasSuffix(host, p) {
			i := strings.Index(n, "/")
			if i > -1 {
				host = host + n[0:i+1]
				n = n[i+1:]
			}
			break
		}
	}

	return normalizeGitHostSpec(host), n
}
func normalizeGitHostSpec(host string) string {
	s := strings.ToLower(host)
	if strings.Contains(s, "github.com") {
		if strings.Contains(s, "git@") || strings.Contains(s, "ssh:") {
			host = "git@github.com:"
		} else {
			host = "https://github.com/"
		}
	}
	if strings.HasPrefix(s, "git::") {
		host = strings.TrimPrefix(s, "git::")
	}
	return host
}

func peelQuery(arg string) (string, string) {

	r, _ := regexp.Compile(refQueryRegex)
	j := r.FindStringIndex(arg)

	if len(j) > 0 {
		return arg[:j[0]], arg[j[0]+len(r.FindString(arg)):]
	}
	return arg, ""
}
