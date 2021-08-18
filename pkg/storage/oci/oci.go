package oci

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gajananan/argocd-interlace/pkg/provenance"
	"github.com/gajananan/argocd-interlace/pkg/sign"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
)

type StorageBackend struct {
	appName            string
	appPath            string
	appDirPath         string
	appSourceRepoUrl   string
	appSourceRevision  string
	appSourceCommitSha string
	imageRef           string
	buildStartedOn     time.Time
	buildFinishedOn    time.Time
}

const (
	StorageBackendOCI = "oci"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha string) (*StorageBackend, error) {
	return &StorageBackend{
		appName:            appName,
		appPath:            appPath,
		appDirPath:         appDirPath,
		appSourceRepoUrl:   appSourceRepoUrl,
		appSourceRevision:  appSourceRevision,
		appSourceCommitSha: appSourceCommitSha,
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {

	// Retrive the bundle image name and tag based on configuration and appName
	imageRef := getImageRef(s.appName)

	s.imageRef = imageRef

	// Check if the there is an existing bundle manifest in the storage
	bundleYAMLBytes, err := getBundleManifest(imageRef)

	if err != nil {
		return nil, err
	}
	return bundleYAMLBytes, nil
}

func (s StorageBackend) StoreManifestSignature() error {

	keyPath := utils.PRIVATE_KEY_PATH
	manifestPath := filepath.Join(s.appDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestPath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	err := sign.SignManifest(s.imageRef, keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Info("Error in signing bundle image err %s", err.Error())
		return err
	}

	return nil
}

func (s StorageBackend) StoreManifestProvenance() error {
	provenance.GenerateProvanance(s.appName, s.appPath, s.appSourceRepoUrl, s.appSourceRevision, s.appSourceCommitSha,
		s.imageRef, s.buildStartedOn, s.buildFinishedOn)
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
	return StorageBackendOCI
}

func getBundleManifest(imageRef string) ([]byte, error) {

	image, err := k8smnfutil.PullImage(imageRef)

	if err != nil {
		log.Info("Error in pulling image err %s", err.Error())
		return nil, err
	}

	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		log.Info("Error in GenerateConcatYAMLsFromImage err %s", err.Error())
		return nil, err
	}
	return concatYAMLbytes, nil
}

func getImageRef(appName string) string {

	imageRegistry := os.Getenv("IMAGE_REGISTRY")

	if imageRegistry == "" {
		log.Info("IMAGE_REGISTRY is empty, please specify in configuration !")
		return ""
	}

	imagePrefix := os.Getenv("IMAGE_PREFIX")

	if imagePrefix == "" {
		log.Info("IMAGE_PREFIX is empty please specify in configuration!")
		return ""
	}

	imageTag := os.Getenv("IMAGE_TAG")

	if imageTag == "" {
		log.Info("IMAGE_TAG is empty please specify in configuration!")
		return ""
	}

	imageName := fmt.Sprintf("%s-%s", imagePrefix, appName)

	imageRef := fmt.Sprintf("%s/%s:%s", imageRegistry, imageName, imageTag)

	return imageRef

}
