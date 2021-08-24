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

package oci

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/provenance"
	"github.com/IBM/argocd-interlace/pkg/sign"
	"github.com/IBM/argocd-interlace/pkg/utils"
	"github.com/google/go-containerregistry/pkg/crane"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
)

type StorageBackend struct {
	appName                     string
	appPath                     string
	appDirPath                  string
	appSourceRepoUrl            string
	appSourceRevision           string
	appSourceCommitSha          string
	appSourcePreiviousCommitSha string
	imageRef                    string
	buildStartedOn              time.Time
	buildFinishedOn             time.Time
}

const (
	StorageBackendOCI = "oci"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string) (*StorageBackend, error) {
	return &StorageBackend{
		appName:                     appName,
		appPath:                     appPath,
		appDirPath:                  appDirPath,
		appSourceRepoUrl:            appSourceRepoUrl,
		appSourceRevision:           appSourceRevision,
		appSourceCommitSha:          appSourceCommitSha,
		appSourcePreiviousCommitSha: appSourcePreiviousCommitSha,
		imageRef:                    getImageRef(appName),
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {

	if s.imageRef == "" {
		return nil, fmt.Errorf("Error in fetching imageRef")
	}
	// Check if the there is an existing bundle manifest in the storage
	bundleYAMLBytes, err := getBundleManifest(s.imageRef)

	if err != nil {
		log.Errorf("Error in retriving bundle manifest image: %s", err.Error())
		return nil, err
	}
	return bundleYAMLBytes, nil
}

func (s StorageBackend) StoreManifestBundle() error {
	log.Infof("Storing manifest in OCI: %s ", s.imageRef)

	keyPath := utils.PRIVATE_KEY_PATH
	manifestPath := filepath.Join(s.appDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestPath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	err := sign.SignManifest(s.imageRef, keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Errorf("Error in signing bundle image: %s", err.Error())
		return err
	}

	log.Infof("Storing manifest provenance for OCI: %s ", s.imageRef)

	imageDigest, err := getDigest(s.imageRef)

	if err != nil {
		log.Errorf("Error in getting digest: %s ", err.Error())
		return err
	}

	err = provenance.GenerateProvanance(s.appName, s.appPath, s.appSourceRepoUrl,
		s.appSourceRevision, s.appSourceCommitSha, s.appSourcePreiviousCommitSha,
		s.imageRef, imageDigest, s.buildStartedOn, s.buildFinishedOn)
	if err != nil {
		log.Errorf("Error in storing provenance: %s", err.Error())
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
	return StorageBackendOCI
}

func getBundleManifest(imageRef string) ([]byte, error) {

	image, err := k8smnfutil.PullImage(imageRef)

	if err != nil {
		log.Infof("Error in pulling image err %s", err.Error())
		return nil, err
	}

	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		log.Infof("Error in GenerateConcatYAMLsFromImage err %s", err.Error())
		return nil, err
	}
	return concatYAMLbytes, nil
}

func getImageRef(appName string) string {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return ""
	}

	imageRegistry := interlaceConfig.OciImageRegistry

	imagePrefix := interlaceConfig.OciImagePrefix

	imageTag := interlaceConfig.OciImageTag

	imageName := fmt.Sprintf("%s-%s", imagePrefix, appName)

	imageRef := fmt.Sprintf("%s/%s:%s", imageRegistry, imageName, imageTag)

	return imageRef

}

func getDigest(src string) (string, error) {

	digest, err := crane.Digest(src)
	if err != nil {
		return "", fmt.Errorf("fetching digest %s: %v", src, err)
	}
	return digest, nil
}
