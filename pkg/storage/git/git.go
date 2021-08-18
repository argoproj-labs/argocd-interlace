package git

import (
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/gajananan/argocd-interlace/pkg/sign"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	billy "github.com/go-git/go-billy/v5"
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
	appName              string
	appPath              string
	appDirPath           string
	appSourceRepoUrl     string
	appSourceRevision    string
	appSourceCommitSha   string
	manifestGitUrl       string
	manifestGitUserId    string
	manifestGitUserEmail string
	manifestGitToken     string
	buildStartedOn       time.Time
	buildFinishedOn      time.Time
	manifest             []byte
	repo                 *git.Repository
	storer               *memory.Storage
	fs                   billy.Filesystem
}

const (
	StorageBackendGit = "git"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
	manifestGitUrl, manifestGitUserId, manifestGitToken string,
) (*StorageBackend, error) {
	return &StorageBackend{
		appName:            appName,
		appPath:            appPath,
		appDirPath:         appDirPath,
		appSourceRepoUrl:   appSourceRepoUrl,
		appSourceRevision:  appSourceRevision,
		appSourceCommitSha: appSourceCommitSha,
		manifestGitUrl:     manifestGitUrl,
		manifestGitUserId:  manifestGitUserId,
		manifestGitToken:   manifestGitToken,
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {

	s.gitClone()

	absFilePath := filepath.Join(s.appName, s.appPath, utils.CONFIG_FILE_NAME)

	log.Info("absFilePath ", absFilePath)
	file, err := s.fs.Open(absFilePath)

	if err != nil {
		log.Fatalf("Error occured while opening file %s :%v", absFilePath, err)
		return nil, err
	}

	var fileContent []byte

	_, err = file.Read(fileContent)
	if err != nil {
		log.Fatalf("Error occured while reading file %s :%v", absFilePath, err)
		return nil, err
	}

	content, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Error occured while reading file %s :%v", absFilePath, err)
		return nil, err
	}

	jsonBytes, err := yaml.YAMLToJSON(content)

	gzipMessage, err := base64.StdEncoding.DecodeString(gjson.Get(string(jsonBytes), "data.message").String())

	gzipTarBall := k8smnfutil.GzipDecompress(gzipMessage)

	yamls, err := k8smnfutil.GetYAMLsInArtifact(gzipTarBall)

	contactYamls := k8smnfutil.ConcatenateYAMLs(yamls)

	return contactYamls, nil
}

func (s StorageBackend) StoreManifestSignature() error {

	manifestPath := filepath.Join(s.appDirPath, utils.MANIFEST_FILE_NAME)

	signedManifestPath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	keyPath := utils.PRIVATE_KEY_PATH

	err := sign.SignManifest("", keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Info("Error in signing manifest err %s", err.Error())
		return err
	}

	configFilePath := filepath.Join(s.appDirPath, utils.CONFIG_FILE_NAME)

	signedManifestFilePath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	name := s.appName + "-manifest-sig"

	out, err := k8smnfutil.CmdExec("/ishield-app/generate_signedcm.sh", signedManifestFilePath, name, configFilePath)

	if err != nil {
		log.Info("error is generating signed configmap ", err.Error())
	}

	log.Debug(out)

	s.gitCloneAndUpdate()

	return nil
}

func (s StorageBackend) StoreManifestProvenance() error {
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

func (s StorageBackend) gitClone() {

	log.Info("Cloning repo ", s.manifestGitUrl)
	s.fs = memfs.New()

	repo, err := git.Clone(memory.NewStorage(), s.fs, &git.CloneOptions{
		URL: s.manifestGitUrl,
		Auth: &http.BasicAuth{
			Username: s.manifestGitUserId,
			Password: s.manifestGitToken,
		},
	})

	if err != nil {
		log.Info("Error in clone repo %s", err.Error())
	}

	s.repo = repo
}

func (s StorageBackend) gitCloneAndUpdate() {

	s.gitClone()

	w, err := s.repo.Worktree()

	absFilePath := filepath.Join(s.appName, s.appPath, utils.CONFIG_FILE_NAME)

	log.Info("absFilePath ", absFilePath)

	s.fs.Remove(absFilePath)

	file, err := s.fs.Create(absFilePath)

	if err != nil {
		log.Fatalf("Error occured while opening file %s :%v", absFilePath, err)
		return
	}

	configFilePath := filepath.Join(s.appDirPath, utils.CONFIG_FILE_NAME)
	configFileBytes, _ := ioutil.ReadFile(filepath.Clean(configFilePath))

	log.Info("configFileBytes ", string(configFileBytes))
	_, err = file.Write(configFileBytes)
	file.Close()

	if err != nil {
		log.Fatalf("Error occured while writing to file %s :%v", absFilePath, err)
		return
	}

	status, _ := w.Status()
	log.Info("Git status before adding new file", status)

	// git add absFilePath
	w.Add(absFilePath)

	// Run git status after the file has been added adding to the worktree
	status, _ = w.Status()
	log.Info("Git status after adding new file ", status)

	// git commit -m $message
	_, err = w.Commit("Added my new file", s.getCommitOptions())
	if err != nil {
		log.Fatalf("Error occured while committing file %s :%v", absFilePath, err)
		return
	}

	status, _ = w.Status()
	log.Info("Git status after commiting new file ", status)

	if status.IsClean() {
		log.Info("Git status after commiting new file ", status.IsClean())
	}

	log.Info("Pushing changes to manifest file ")

	//Push the code to the remote
	err = s.repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: s.manifestGitUserId,
			Password: s.manifestGitToken,
		},
	})
	if err != nil {
		log.Info("Error in pushing to repo %s", err.Error())
	}
}

func (s StorageBackend) getCommitOptions() *git.CommitOptions {

	return &git.CommitOptions{
		Author: &object.Signature{
			Name:  s.manifestGitUserId,
			Email: s.manifestGitUserEmail,
			When:  time.Now(),
		},
	}
}
