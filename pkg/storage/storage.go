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

package storage

import (
	"time"

	iprof "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/annotation"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/repository"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/resource"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/pkg/errors"
	"k8s.io/client-go/rest"
)

var configuredStorageBackends = []string{
	annotation.StorageBackendAnnotation,
	resource.StorageBackendResource,
	repository.StorageBackendRepository,
}

type StorageBackend interface {
	GetLatestManifestContent() ([]byte, error)
	StoreManifestBundle(sourceVerifed bool, privkeyBytes []byte) error
	StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time, sourceVerifed bool, privkeyBytes []byte) error
	GetProvenanceManager() provenance.ProvenanceManager
	UploadTLogEnabled() bool // TODO: TLog should be an independent storageBackend instead of common configuration
	GetDestinationString() string
	Type() string
}

type StorageConfig struct {
	// common settings
	ManifestStorageType string
	AppData             application.ApplicationData
	Profile             *iprof.InterlaceProfile

	// resource storage
	AppProvClientset     appprovClientset.Interface
	InterlaceNS          string
	MaxResultsInResource int

	// remote storage
	APIURL      string
	APIUsername string
	APIPassword string

	UploadTLog bool
}

func InitializeStorageBackends(c StorageConfig, kubeConfig *rest.Config) (map[string]StorageBackend, error) {
	storageBackends := map[string]StorageBackend{}
	for _, backendType := range configuredStorageBackends {
		if c.ManifestStorageType == backendType {
			switch backendType {
			case annotation.StorageBackendAnnotation:
				annotationStorageBackend, err := annotation.NewStorageBackend(c.AppData, c.UploadTLog)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = annotationStorageBackend
			case resource.StorageBackendResource:
				resourceStorageBackend, err := resource.NewStorageBackend(c.AppData, c.AppProvClientset, c.InterlaceNS, c.MaxResultsInResource, c.UploadTLog)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = resourceStorageBackend
			case repository.StorageBackendRepository:
				srcConf := c.Profile.Spec.Protection.PolicySource
				gitSecretName := c.Profile.Spec.Protection.PolicySource.AuthSecret
				secret, err := utils.GetSecret(kubeConfig, c.InterlaceNS, gitSecretName)
				if err != nil {
					return nil, errors.Wrap(err, "failed to get secret")
				}
				user := secret.Data["user"]
				token := secret.Data["token"]
				email := secret.Data["email"]
				gitUser := string(user)
				gitToken := string(token)
				gitEmail := string(email)
				repositoryStorageBackend, err := repository.NewStorageBackend(c.AppData, c.AppProvClientset, srcConf, gitUser, gitToken, gitEmail, c.MaxResultsInResource, c.UploadTLog)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = repositoryStorageBackend
			}
		}
	}

	return storageBackends, nil

}
