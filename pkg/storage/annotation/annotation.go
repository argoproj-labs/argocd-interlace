//
// Copyright 2022 IBM Corporation
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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	helmprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/helm"
	kustprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/kustomize"
	"github.com/argoproj-labs/argocd-interlace/pkg/sign"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
)

const (
	StorageBackendAnnotation = "annotation"
)

type AnnotationStorageBackend struct {
	appData application.ApplicationData
	provMgr provenance.ProvenanceManager

	interlaceNS           string
	uploadTLog            bool
	rekorURL              string
	manifestImage         string
	registrySecret        string
	allowInsecureRegistry bool
	kubeConfig            *rest.Config
}

func NewStorageBackend(appData application.ApplicationData, interlaceNS string, uploadTLog bool, rekorURL string, manifestImage string, registrySecret string, allowInsecureRegistry bool, kubeConfig *rest.Config) (*AnnotationStorageBackend, error) {
	return &AnnotationStorageBackend{
		appData:               appData,
		interlaceNS:           interlaceNS,
		uploadTLog:            uploadTLog,
		rekorURL:              rekorURL,
		manifestImage:         manifestImage,
		registrySecret:        registrySecret,
		allowInsecureRegistry: allowInsecureRegistry,
		kubeConfig:            kubeConfig,
	}, nil
}

func (s *AnnotationStorageBackend) GetLatestManifestContent() ([]byte, error) {
	return nil, nil
}

func (s *AnnotationStorageBackend) StoreManifestBundle(sourceVerifed bool, manifestBytes, privkeyBytes []byte) error {

	signedManifestPath := filepath.Join(s.appData.AppDirPath, config.SIGNED_MANIFEST_FILE_NAME)

	log.Debugf("manifest bytes: %s", string(manifestBytes))

	manifestFile, err := ioutil.TempFile("", "manifest.yaml")
	if err != nil {
		return errors.Wrap(err, "error in creating a temp manifest file")
	}
	defer os.Remove(manifestFile.Name())

	_, err = manifestFile.Write(manifestBytes)
	if err != nil {
		return errors.Wrap(err, "error in saving the manifest as a temp file")
	}
	manifestPath := manifestFile.Name()

	doSigning := true
	// if signing key is empty, do not sign the manifest and return here
	if string(privkeyBytes) == "" {
		log.Warnf("signing key is empty, so skip signing the manifest")
		doSigning = false
	}
	if doSigning {
		privkeyFile, err := ioutil.TempFile("", "privkey")
		if err != nil {
			return errors.Wrap(err, "error in creating a temp key file")
		}
		defer os.Remove(privkeyFile.Name())

		_, err = privkeyFile.Write(privkeyBytes)
		if err != nil {
			return errors.Wrap(err, "error in saving the signing key as a temp file")
		}

		keyPath := privkeyFile.Name()
		signedBytes, err := sign.SignManifest(keyPath, manifestPath, signedManifestPath)
		if err != nil {
			return errors.Wrap(err, "error in signing manifest")
		}
		manifestBytes = signedBytes
	}
	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(manifestBytes)

	log.Info("len(manifestYAMLs): ", len(manifestYAMLs))
	interlaceConfig, err := config.GetInterlaceConfig()

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

		isSignatureresource := false
		log.Info("resourceLabels ", resourceLabels)

		if rscLabel, ok := resourceLabels[interlaceConfig.SignatureResourceLabel]; ok {
			isSignatureresource, err = strconv.ParseBool(rscLabel)
			if err != nil {
				log.Errorf("failed to parse label value `%s`; err: %s", rscLabel, err.Error())
			}

		}
		log.Info("isSignatureresource :", isSignatureresource)
		if isSignatureresource {
			if namespace == "" {
				namespace = s.appData.AppDestinationNamespace
			}
			log.Info("Patch kind:", kind, " name:", resourceName, " in namespace:", namespace)

			annotations = k8smnfutil.GetAnnotationsInYAML(item)

			message := "null"
			signature := "null"
			if sourceVerifed {
				message = annotations[config.MSG_ANNOTATION_NAME]
				signature = annotations[config.SIG_ANNOTATION_NAME]
			}

			patchData, err := preparePatch(message, signature, kind)
			if err != nil {
				return errors.Wrap(err, "error in creating patch for application resource config")
			}

			log.Info("len(patchData)", len(patchData))

			log.Infof("[%s] Interlace attaches signature to resource as annotation:", s.appData.AppName)

			err = argoutil.ApplyResourcePatch(kind, resourceName, namespace, s.appData.AppName, patchData)
			// err = argoutil.PatchResource(interlaceConfig.ArgocdApiBaseUrl, s.appData.AppName, namespace, resourceName, gv.Group, gv.Version, kind, patchData)

			if err != nil {
				return errors.Wrap(err, "error in patching application resource config")
			}
		}
	}

	if err != nil {
		return errors.Wrap(err, "error in getting digest")
	}

	if s.manifestImage != "" {
		secretKeychain := &utils.SecretKeyChain{
			Name:       s.registrySecret,
			Namespace:  s.interlaceNS,
			KubeConfig: s.kubeConfig,
		}
		err = utils.UploadManifestImage(manifestBytes, s.manifestImage, s.allowInsecureRegistry, secretKeychain)
		if err != nil {
			return errors.Wrap(err, "failed to upload manifest image")
		}
		err = utils.SignImage(s.manifestImage, privkeyBytes, "", s.uploadTLog, s.allowInsecureRegistry, secretKeychain)
		if err != nil {
			return errors.Wrap(err, "failed to sign the uploaded manifest image")
		}
	}
	return nil
}

func preparePatch(message, signature, kind string) ([]byte, error) {

	patchData := map[string]interface{}{}
	patchDataSub := map[string]interface{}{}
	if kind == "ConfigMap" {
		if message != "" {
			patchDataSub["message"] = message
		}
		if signature != "" {
			patchDataSub["signature"] = signature
		}
		patchData["data"] = patchDataSub
	} else {
		msgAnnot := config.MSG_ANNOTATION_NAME
		if message != "" {
			patchDataSub[msgAnnot] = message
		}
		sigAnnot := config.SIG_ANNOTATION_NAME
		if signature != "" {
			patchDataSub[sigAnnot] = signature
		}
		patchData["metadata"] = map[string]interface{}{
			"annotations": patchDataSub,
		}
	}
	return json.Marshal(patchData)
}

func (s *AnnotationStorageBackend) StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time, sourceVerified bool, privkeyBytes []byte) error {
	var target, hash string
	var err error
	if s.manifestImage != "" {
		target = s.manifestImage
		hash, err = utils.GetImageHash(target)
		if err != nil {
			return errors.Wrap(err, "failed to get image digest")
		}
	} else {
		target = filepath.Join(s.appData.AppDirPath, config.MANIFEST_FILE_NAME)
		hash, err = utils.ComputeHash(target)
		if err != nil {
			return errors.Wrap(err, "failed to compute hash value of the manifest file")
		}
	}

	var provMgr provenance.ProvenanceManager
	if s.appData.IsHelm {
		provMgr, _ = helmprov.NewProvenanceManager(s.appData)
	} else {
		provMgr, _ = kustprov.NewProvenanceManager(s.appData)
	}
	err = provMgr.GenerateProvenance(target, hash, privkeyBytes, s.uploadTLog, s.rekorURL, buildStartedOn, buildFinishedOn)
	if err != nil {
		return errors.Wrap(err, "failed to generate provenance data")
	}
	s.provMgr = provMgr

	return nil
}

func (b *AnnotationStorageBackend) UploadTLogEnabled() bool {
	return b.uploadTLog
}

func (b *AnnotationStorageBackend) GetDestinationString() string {
	return "annotation"
}

func (b *AnnotationStorageBackend) GetProvenanceManager() provenance.ProvenanceManager {
	return b.provMgr
}

func (b *AnnotationStorageBackend) Type() string {
	return StorageBackendAnnotation
}
