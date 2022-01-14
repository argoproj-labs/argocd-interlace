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
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/IBM/argocd-interlace/pkg/application"
	"github.com/IBM/argocd-interlace/pkg/config"
	helmprov "github.com/IBM/argocd-interlace/pkg/provenance/helm"
	kustprov "github.com/IBM/argocd-interlace/pkg/provenance/kustomize"
	"github.com/IBM/argocd-interlace/pkg/sign"
	"github.com/IBM/argocd-interlace/pkg/utils"
	"github.com/ghodss/yaml"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	StorageBackendAnnotation = "annotation"
)

type StorageBackend struct {
	appData application.ApplicationData
}

func NewStorageBackend(appData application.ApplicationData) (*StorageBackend, error) {
	return &StorageBackend{
		appData: appData,
	}, nil
}

func (s StorageBackend) GetLatestManifestContent() ([]byte, error) {
	return nil, nil
}

func (s StorageBackend) StoreManifestBundle(sourceVerifed bool) error {

	keyPath := utils.PRIVATE_KEY_PATH
	manifestPath := filepath.Join(s.appData.AppDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestPath := filepath.Join(s.appData.AppDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	signedBytes, err := sign.SignManifest(keyPath, manifestPath, signedManifestPath)

	if err != nil {
		log.Errorf("Error in signing manifest: %s", err.Error())
		return err
	}

	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(signedBytes)

	log.Info("len(manifestYAMLs): ", len(manifestYAMLs))

	var annotations map[string]string
	for _, item := range manifestYAMLs {

		var obj unstructured.Unstructured
		err := yaml.Unmarshal(item, &obj)
		if err != nil {
			log.Errorf("Error unmarshling: %s", err.Error())
		}

		kind := obj.GetKind()
		resourceName := obj.GetName()
		namespace := obj.GetNamespace()

		resourceLabels := obj.GetLabels()

		log.Info("kind :", kind, " resourceName ", resourceName, " namespace", namespace)
		interlaceConfig, err := config.GetInterlaceConfig()

		isSignatureresource := false
		log.Info("resourceLabels ", resourceLabels)

		if rscLabel, ok := resourceLabels[interlaceConfig.SignatureResourceLabel]; ok {
			isSignatureresource, _ = strconv.ParseBool(rscLabel)
		}

		log.Info("isSignatureresource :", isSignatureresource)

		if isSignatureresource {
			log.Info("Patch kind:", kind, " name:", resourceName, " in namespace:", namespace)

			annotations = k8smnfutil.GetAnnotationsInYAML(item)

			message := "null"
			signature := "null"
			if sourceVerifed {
				message = annotations[utils.MSG_ANNOTATION_NAME]
				signature = annotations[utils.SIG_ANNOTATION_NAME]
			}

			patchData, err := preparePatch(message, signature, kind)
			if err != nil {
				log.Errorf("Error in creating patch for application resource config: %s", err.Error())
				return err
			}

			log.Info("len(patchData)", len(patchData))

			log.Infof("[INFO][%s] Interlace attaches signature to resource as annotation:", s.appData.AppName)

			err = utils.ApplyResourcePatch(kind, resourceName, namespace, s.appData.AppName, patchData)

			if err != nil {
				log.Errorf("Error in patching application resource config: %s", err.Error())
				return nil
			}

		}

	}

	if err != nil {
		log.Errorf("Error in getting digest: %s ", err.Error())
		return err
	}
	return nil
}

func preparePatch(message, signature, kind string) ([]string, error) {

	var patchData []string
	if kind == "ConfigMap" {

		patchSig := fmt.Sprintf("{\"%s\": {\"%s\": \"%s\"}}",
			"data", "signature", signature)
		patchData = append(patchData, patchSig)
		patchMsg := fmt.Sprintf("{\"%s\": {\"%s\": \"%s\"}}",
			"data", "message", message)
		patchData = append(patchData, patchMsg)
	} else {
		sigAnnot := utils.SIG_ANNOTATION_NAME
		patchSig := fmt.Sprintf("{\"%s\": { \"%s\" : {\"%s\": \"%s\"}}}",
			"metadata", "annotations", sigAnnot, signature)
		patchData = append(patchData, patchSig)

		msgAnnot := utils.MSG_ANNOTATION_NAME
		patchMsg := fmt.Sprintf("{\"%s\": { \"%s\" : {\"%s\": \"%s\"}}}",
			"metadata", "annotations", msgAnnot, message)

		patchData = append(patchData, patchMsg)
	}

	return patchData, nil
}

func (s StorageBackend) StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time) error {
	manifestPath := filepath.Join(s.appData.AppDirPath, utils.MANIFEST_FILE_NAME)
	computedFileHash, err := utils.ComputeHash(manifestPath)

	if s.appData.IsHelm {
		prov, _ := helmprov.NewProvenance(s.appData)
		err = prov.GenerateProvanance(manifestPath, computedFileHash, true, buildStartedOn, buildFinishedOn)

		if err != nil {
			log.Errorf("Error in storing provenance: %s", err.Error())
			return err
		}
	} else {
		prov, _ := kustprov.NewProvenance(s.appData)
		err = prov.GenerateProvanance(manifestPath, computedFileHash, true, buildStartedOn, buildFinishedOn)

		if err != nil {
			log.Errorf("Error in storing provenance: %s", err.Error())
			return err
		}
	}

	return nil
}

func (b *StorageBackend) Type() string {
	return StorageBackendAnnotation
}
