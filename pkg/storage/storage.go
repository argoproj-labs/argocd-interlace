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

	"github.com/IBM/argocd-interlace/pkg/storage/annotation"
	"github.com/IBM/argocd-interlace/pkg/storage/oci"
)

type StorageBackend interface {
	GetLatestManifestContent() ([]byte, error)
	StoreManifestBundle() error
	StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time) error
	Type() string
}

func InitializeStorageBackends(appName, appPath, appDirPath, clusterUrl,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha,
	manifestStorageType, clusterName string) (map[string]StorageBackend, error) {

	configuredStorageBackends := []string{oci.StorageBackendOCI, annotation.StorageBackendAnnotation}

	storageBackends := map[string]StorageBackend{}
	for _, backendType := range configuredStorageBackends {
		if manifestStorageType == backendType {
			switch backendType {
			case oci.StorageBackendOCI:

				ociStorageBackend, err := oci.NewStorageBackend(appName, appPath, appDirPath,
					appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = ociStorageBackend
			case annotation.StorageBackendAnnotation:

				annotationStorageBackend, err := annotation.NewStorageBackend(appName, appPath, appDirPath,
					appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha)
				if err != nil {
					return nil, err
				}
				storageBackends[backendType] = annotationStorageBackend

			}
		}
	}

	return storageBackends, nil

}
