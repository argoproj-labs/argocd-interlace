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

package oci

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	helmprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/helm"
	kustprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/kustomize"
	"github.com/argoproj-labs/argocd-interlace/pkg/sign"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	StorageBackendOCI = "oci"
)

type OCIStorageBackend struct {
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

func NewStorageBackend(appData application.ApplicationData, interlaceNS string, uploadTLog bool, rekorURL, manifestImage string, registrySecret string, allowInsecureRegistry bool, kubeConfig *rest.Config) (*OCIStorageBackend, error) {
	return &OCIStorageBackend{
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

func (s *OCIStorageBackend) GetLatestManifestContent() ([]byte, error) {
	return nil, nil
}

func (s *OCIStorageBackend) StoreManifestBundle(sourceVerifed bool, manifestBytes, privkeyBytes []byte) error {
	log.Debugf("manifest bytes: %s", string(manifestBytes))
	dir, err := os.MkdirTemp("", "manifest-bundle")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	manifestPath := filepath.Join(dir, "manifest.yaml")
	err = os.WriteFile(manifestPath, manifestBytes, 0644)
	if err != nil {
		return err
	}

	signedManifestPath := filepath.Join(s.appData.AppDirPath, config.SIGNED_MANIFEST_FILE_NAME)

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
		log.Info("[DEBUG] signedBytes: ", string(signedBytes))
	}
	log.Info("[DEBUG] manifestBytes before split: ", string(manifestBytes))
	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(manifestBytes)

	log.Info("len(manifestYAMLs): ", len(manifestYAMLs))

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

	return nil
}

func (s *OCIStorageBackend) StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time, sourceVerified bool, privkeyBytes []byte) error {
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

	prov := provMgr.GetProvenance()
	provBytes, _ := json.Marshal(prov)
	log.Infof("[DEBUG] provenance: %s", string(provBytes))
	return nil
}

func (b *OCIStorageBackend) UploadTLogEnabled() bool {
	return b.uploadTLog
}

func (b *OCIStorageBackend) GetDestinationString() string {
	return fmt.Sprintf("ApplicationProvenance `%s`", b.appData.AppName)
}

func (b *OCIStorageBackend) GetProvenanceManager() provenance.ProvenanceManager {
	return b.provMgr
}

func (b *OCIStorageBackend) Type() string {
	return StorageBackendOCI
}
