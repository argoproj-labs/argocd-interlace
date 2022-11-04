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

package storage

import (
	"time"

	iprof "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/annotation"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/oci"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/resource"
	"k8s.io/client-go/rest"
)

var configuredStorageBackends = []string{
	annotation.StorageBackendAnnotation,
	resource.StorageBackendResource,
	oci.StorageBackendOCI,
}

type StorageBackend interface {
	GetLatestManifestContent() ([]byte, error)
	StoreManifestBundle(sourceVerifed bool, manifestBytes, privkeyBytes []byte) error
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
	RekorURL   string

	// manifest image
	ManifestImage         string
	RegistrySecret        string
	AllowInsecureRegistry bool
}

func InitializeStorageBackends(c StorageConfig, kubeConfig *rest.Config) (map[string]StorageBackend, error) {
	storageBackends := map[string]StorageBackend{}
	for _, backendType := range configuredStorageBackends {
		if c.ManifestStorageType == backendType {
			switch backendType {
			case annotation.StorageBackendAnnotation:
				annotationStorageBackend, err := annotation.NewStorageBackend(c.AppData, c.InterlaceNS, c.UploadTLog, c.RekorURL, c.ManifestImage, c.RegistrySecret, c.AllowInsecureRegistry, kubeConfig)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = annotationStorageBackend
			case resource.StorageBackendResource:
				resourceStorageBackend, err := resource.NewStorageBackend(c.AppData, c.AppProvClientset, c.InterlaceNS, c.MaxResultsInResource, c.UploadTLog, c.RekorURL, c.ManifestImage, c.RegistrySecret, c.AllowInsecureRegistry, kubeConfig)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = resourceStorageBackend
			case oci.StorageBackendOCI:
				ociStorageBackend, err := oci.NewStorageBackend(c.AppData, c.InterlaceNS, c.UploadTLog, c.RekorURL, c.ManifestImage, c.RegistrySecret, c.AllowInsecureRegistry, kubeConfig)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = ociStorageBackend
			}
		}
	}

	return storageBackends, nil

}
