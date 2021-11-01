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

package annotation

import (
	"path/filepath"
	"time"

	"github.com/IBM/argocd-interlace/pkg/provenance"
	"github.com/IBM/argocd-interlace/pkg/sign"
	"github.com/IBM/argocd-interlace/pkg/utils"
	"github.com/ghodss/yaml"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type StorageBackend struct {
	appName                     string
	appPath                     string
	appDirPath                  string
	appSourceRepoUrl            string
	appSourceRevision           string
	appSourceCommitSha          string
	appSourcePreiviousCommitSha string
	buildStartedOn              time.Time
	buildFinishedOn             time.Time
}

const (
	StorageBackendAnnotation = "annotation"
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
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {
	return nil, nil
}

func (s StorageBackend) StoreManifestBundle() error {

	keyPath := utils.PRIVATE_KEY_PATH
	manifestPath := filepath.Join(s.appDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestPath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	signedBytes, err := sign.SignManifest("", keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Errorf("Error in signing bundle image: %s", err.Error())
		return err
	}

	log.Info("signedBytes: ", string(signedBytes))

	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(signedBytes)

	var annotations map[string]string
	for _, item := range manifestYAMLs {

		var obj unstructured.Unstructured
		err := yaml.Unmarshal(item, &obj)
		if err != nil {
			log.Errorf("Error unmarshling: %s", err.Error())
		}

		kind := obj.GetKind()

		log.Info("Before ----->>>", obj.GetKind(), obj.GetName(), obj.GetNamespace())

		if kind == "Policy" {
			annotations = k8smnfutil.GetAnnotationsInYAML(item)

			log.Info("annotations ", annotations)

			log.Info("annotations.message ", annotations["cosign.sigstore.dev/message"])

			log.Info("annotations.signature ", annotations["cosign.sigstore.dev/signature"])

			name := obj.GetName()
			namespace := obj.GetNamespace()
			utils.ApplyPatch(name, namespace, obj, annotations)

			log.Infof("[INFO][%s] Interlace attaches signature to policy as annotation:", s.appName)

			break
		}

	}

	if err != nil {
		log.Errorf("Error in getting digest: %s ", err.Error())
		return err
	}
	return nil
}

func (s StorageBackend) StoreManifestProvenance() error {
	err := provenance.GenerateProvanance(s.appName, s.appPath, s.appSourceRepoUrl,
		s.appSourceRevision, s.appSourceCommitSha, s.appSourcePreiviousCommitSha,
		"", "", s.buildStartedOn, s.buildFinishedOn, true)
	if err != nil {
		log.Errorf("Error in storing provenance: %s", err.Error())
		return err
	}

	return nil
}

func GetKindInYAML(yamlBytes []byte) string {

	var obj unstructured.Unstructured
	err := yaml.Unmarshal(yamlBytes, &obj)
	if err != nil {
		return ""
	}
	return obj.GetKind()
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
	return StorageBackendAnnotation
}
