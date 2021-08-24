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

package git

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/provenance"
	"github.com/IBM/argocd-interlace/pkg/sign"
	"github.com/IBM/argocd-interlace/pkg/utils"
	"github.com/go-git/go-billy/v5"
	memfs "github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	memory "github.com/go-git/go-git/v5/storage/memory"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"sigs.k8s.io/yaml"
)

type StorageBackend struct {
	appName                     string
	appPath                     string
	appDirPath                  string
	appSourceRepoUrl            string
	appSourceRevision           string
	appSourceCommitSha          string
	appSourcePreiviousCommitSha string
	manifestGitUrl              string
	manifestGitUserId           string
	manifestGitUserEmail        string
	manifestGitToken            string
	buildStartedOn              time.Time
	buildFinishedOn             time.Time
}

const (
	StorageBackendGit = "git"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string,
) (*StorageBackend, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return nil, err
	}

	return &StorageBackend{
		appName:                     appName,
		appPath:                     appPath,
		appDirPath:                  appDirPath,
		appSourceRepoUrl:            appSourceRepoUrl,
		appSourceRevision:           appSourceRevision,
		appSourceCommitSha:          appSourceCommitSha,
		appSourcePreiviousCommitSha: appSourcePreiviousCommitSha,
		manifestGitUrl:              interlaceConfig.ManifestGitUrl,
		manifestGitUserId:           interlaceConfig.ManifestGitUserId,
		manifestGitUserEmail:        interlaceConfig.ManifestGitUserEmail,
		manifestGitToken:            interlaceConfig.ManifestGitToken,
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {

	fs, _, err := gitClone(s.manifestGitUrl, s.manifestGitUserId, s.manifestGitToken)
	if err != nil {
		log.Errorf("Error occured while cloning %s", err.Error())
		return nil, err
	}

	configFileName := fmt.Sprintf("%s-%s", s.appName, utils.CONFIG_FILE_NAME)
	configFilePath := filepath.Join(utils.MANIFEST_DIR, configFileName)

	file, err := fs.Open(configFilePath)

	if err != nil {
		log.Errorf("Error occured while opening file %s :%v", configFilePath, err)
		return nil, err
	}

	var fileContent []byte

	_, err = file.Read(fileContent)
	if err != nil {
		log.Errorf("Error occured while reading file %s :%v", configFilePath, err)
		return nil, err
	}

	content, err := ioutil.ReadAll(file)
	if err != nil {
		log.Errorf("Error occured while reading file %s :%v", configFilePath, err)
		return nil, err
	}

	jsonBytes, err := yaml.YAMLToJSON(content)
	if err != nil {
		log.Errorf("Error in converting from yaml to json: %s", err.Error())
		return nil, err
	}

	gzipMessage, err := base64.StdEncoding.DecodeString(gjson.Get(string(jsonBytes), "data.message").String())

	if err != nil {
		log.Errorf("Error in decoding signed manifest: %s", err.Error())
		return nil, err
	}

	gzipTarBall := k8smnfutil.GzipDecompress(gzipMessage)

	yamls, err := k8smnfutil.GetYAMLsInArtifact(gzipTarBall)

	if err != nil {
		log.Errorf("Error in extracting yamls from manifest: %s", err.Error())
		return nil, err
	}

	contactYamls := k8smnfutil.ConcatenateYAMLs(yamls)

	return contactYamls, nil
}

func (s StorageBackend) StoreManifestBundle() error {

	manifestPath := filepath.Join(s.appDirPath, utils.MANIFEST_FILE_NAME)

	signedManifestPath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	keyPath := utils.PRIVATE_KEY_PATH

	err := sign.SignManifest("", keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Errorf("Error in signing manifest err %s", err.Error())
		return err
	}

	newConfigFilePath := filepath.Join(s.appDirPath, utils.CONFIG_FILE_NAME)

	signedManifestFilePath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	fileName := signedManifestFilePath
	log.Infof("Storing manifest provenance for GIT: %s ", fileName)
	fileHash, err := utils.Sha256Hash(signedManifestFilePath)
	if err != nil {
		log.Errorf("Error in retrieving files digest : %s", err.Error())
		return err
	}

	err = provenance.GenerateProvanance(s.appName, s.appPath, s.appSourceRepoUrl,
		s.appSourceRevision, s.appSourceCommitSha, s.appSourcePreiviousCommitSha,
		fileName, fileHash, s.buildStartedOn, s.buildFinishedOn)
	if err != nil {
		log.Errorf("Error in storing provenance: %s", err.Error())
		return err
	}

	provFilePath := filepath.Join(s.appDirPath, utils.PROVENANCE_FILE_NAME)

	name := s.appName + "-manifest-sig"

	out, err := k8smnfutil.CmdExec("/interlace-app/generate_manifest_bundle.sh", signedManifestFilePath, provFilePath, name, newConfigFilePath)

	if err != nil {
		log.Errorf("Error in generating signed configmap: %s", err.Error())
		return err
	}

	log.Debug("Results from command execution: ", out)

	err = gitCloneAndUpdate(s.appName, s.appPath, s.appDirPath,
		s.manifestGitUrl, s.manifestGitUserId, s.manifestGitUserEmail, s.manifestGitToken)

	if err != nil {
		log.Errorf("Error in cloning manifest repo and updating signed configmap: %s", err.Error())
		return err
	}
	return nil
}

func (s StorageBackend) SetBuildStartedOn(buildStartedOn time.Time) error {
	s.buildStartedOn = buildStartedOn
	return nil
}

func (s StorageBackend) SetBuildFinishedOn(buildFinishedOn time.Time) error {
	s.buildFinishedOn = buildFinishedOn
	return nil
}

func (b *StorageBackend) Type() string {
	return StorageBackendGit
}

func gitCloneAndUpdate(appName, appPath, appDirPath, gitUrl, gitUser, gitUserEmail, gitToken string) error {

	fs, repo, err := gitClone(gitUrl, gitUser, gitToken)
	if err != nil {
		log.Errorf("Error in cloning repo %s", err.Error())
		return err
	}

	w, err := repo.Worktree()
	if err != nil {
		log.Errorf("Error occured: %s", err.Error())
		return err
	}

	//absFilePath := filepath.Join(appName, appPath, utils.CONFIG_FILE_NAME)
	//absFilePath := filepath.Join(appName, utils.CONFIG_FILE_NAME)
	configFileName := fmt.Sprintf("%s-%s", appName, utils.CONFIG_FILE_NAME)
	configFilePath := filepath.Join(utils.MANIFEST_DIR, configFileName)

	log.Debug("configFilePath ", configFilePath)

	_, err = fs.Lstat(configFilePath)
	if err == nil {
		err = fs.Remove(configFilePath)
		if err != nil {
			log.Errorf("Error occured while remving old file %s: %s", configFilePath, err.Error())
			return err
		}
	}

	newConfigFilePath := filepath.Join(appDirPath, utils.CONFIG_FILE_NAME)

	configFileBytes, err := ioutil.ReadFile(filepath.Clean(newConfigFilePath))
	if err != nil {
		log.Errorf("Error occured while reading file %s: %s", newConfigFilePath, err.Error())
		return err
	}

	file, err := fs.Create(configFilePath)
	if err != nil {
		log.Errorf("Error occured while opening file %s: %s", configFilePath, err.Error())
		return err
	}

	log.Debug("configFileBytes ", string(configFileBytes))
	_, err = file.Write(configFileBytes)
	if err != nil {
		log.Errorf("Error occured while writing to file %s :%v", newConfigFilePath, err)
		return err
	}
	file.Close()

	status, _ := w.Status()
	log.Debug("Git status before adding new file", status)

	// git add absFilePath
	_, err = w.Add(configFilePath)
	if err != nil {
		log.Errorf("Error occured adding update file %s :%s", configFilePath, err.Error())
		return err
	}
	// Run git status after the file has been added adding to the worktree
	status, _ = w.Status()
	log.Debug("Git status after adding new file ", status)

	// git commit -m $message
	_, err = w.Commit("Added my new file", getCommitOptions(gitUser, gitUserEmail))
	if err != nil {
		log.Errorf("Error occured while committing file %s :%v", configFilePath, err)
		return err
	}

	status, _ = w.Status()
	log.Debug("Git status after commiting new file ", status)

	if status.IsClean() {
		log.Debug("Git status after commiting new file ", status.IsClean())
	}

	log.Info("Pushing changes to manifest file ")

	//Push the code to the remote
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: gitUser,
			Password: gitToken,
		},
	})
	if err != nil {
		log.Errorf("Error in pushing to repo %s", err.Error())
		return err
	}
	return nil
}

func getCommitOptions(gitUser, gitUserEmail string) *git.CommitOptions {

	return &git.CommitOptions{
		Author: &object.Signature{
			Name:  gitUser,
			Email: gitUserEmail,
			When:  time.Now(),
		},
	}
}

func gitClone(gitUrl, gitUser, gitToken string) (billy.Filesystem, *git.Repository, error) {

	log.Info("Cloning repo ", gitUrl)
	fs := memfs.New()

	repo, err := git.Clone(memory.NewStorage(), fs, &git.CloneOptions{
		URL: gitUrl,
		Auth: &http.BasicAuth{
			Username: gitUser,
			Password: gitToken,
		},
	})

	if err != nil {
		log.Errorf("Error in clone repo %s", err.Error())
		return nil, nil, err
	}
	log.Info("Succesfully cloned repo ", gitUrl)
	return fs, repo, nil
}
