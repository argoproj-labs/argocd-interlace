package storage

import (
	"time"

	"github.com/gajananan/argocd-interlace/pkg/storage/git"
	"github.com/gajananan/argocd-interlace/pkg/storage/oci"
)

type StorageBackend interface {
	GetLatestManifestContent() ([]byte, error)
	StoreManifestSignature() error
	StoreManifestProvenance() error
	SetBuildStartedOn(buildStartedOn time.Time) error
	SetBuildFinishedOn(buildFinishedOn time.Time) error
	Type() string
}

func InitializeStorageBackends(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
	manifestGitUrl, manifestGitUserId, manifestGitUserEmail, manifestGitToken string) (map[string]StorageBackend, error) {

	//configuredStorageBackends := []string{oci.StorageBackendOCI}
	configuredStorageBackends := []string{git.StorageBackendGit}

	storageBackends := map[string]StorageBackend{}
	for _, backendType := range configuredStorageBackends {
		switch backendType {
		case oci.StorageBackendOCI:

			ociStorageBackend, err := oci.NewStorageBackend(appName, appPath, appDirPath,
				appSourceRepoUrl, appSourceRevision, appSourceCommitSha)
			if err != nil {
				return nil, err
			}
			storageBackends[backendType] = ociStorageBackend

		case git.StorageBackendGit:
			gitStorageBackend, err := git.NewStorageBackend(appName, appPath, appDirPath,
				appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
				manifestGitUrl, manifestGitUserId, manifestGitToken)
			if err != nil {
				return nil, err
			}
			storageBackends[backendType] = gitStorageBackend
		}

	}

	return storageBackends, nil

}
