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

package interlace

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/manifest"
	"github.com/IBM/argocd-interlace/pkg/provenance"
	"github.com/IBM/argocd-interlace/pkg/storage"
	"github.com/IBM/argocd-interlace/pkg/storage/git"
	"github.com/IBM/argocd-interlace/pkg/utils"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	log "github.com/sirupsen/logrus"
)

func CreateEventHandler(app *appv1.Application) error {

	appName := app.ObjectMeta.Name
	appServer := app.Spec.Destination.Server
	// Do not use app.Status  in create event.
	appSourceRepoUrl := app.Spec.Source.RepoURL
	appSourceRevision := app.Spec.Source.TargetRevision
	appSourceCommitSha := ""
	// Create does not have app.Status.Sync.Revision information, we need to extract commitsha by API
	commitSha := provenance.GitLatestCommitSha(app.Spec.Source.RepoURL, app.Spec.Source.TargetRevision)
	if commitSha != "" {
		appSourceCommitSha = commitSha
	}

	appPath := app.Spec.Source.Path
	appSourcePreiviousCommitSha := ""
	err := signManifestAndGenerateProvenance(appName, appPath, appServer,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, true,
	)
	if err != nil {
		return err
	}
	return nil
}

// Handles update events for the Application CRD
// Triggers the following steps:
// Retrive latest manifest via ArgoCD api
// Sign manifest
// Generate provenance record
// Store signed manifest, provenance record in OCI registry/Git
func UpdateEventHandler(oldApp, newApp *appv1.Application) error {

	generateManifest := false
	created := false
	if oldApp.Status.Health.Status == "" &&
		oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "" &&
		newApp.Status.Health.Status == "Missing" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		// This branch handle the case in which app is newly created,
		// the follow updates contains the necessary information (commit hash etc.)
		generateManifest = true
		created = true
	} else if oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "Synced" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		// This branch handle the case in which app is being updated,
		// the updates contains the necessary information (commit hash etc.)
		generateManifest = true
	}

	if generateManifest {

		appName := newApp.ObjectMeta.Name
		appPath := newApp.Status.Sync.ComparedTo.Source.Path
		appSourceRepoUrl := newApp.Status.Sync.ComparedTo.Source.RepoURL
		appSourceRevision := newApp.Status.Sync.ComparedTo.Source.TargetRevision
		appSourceCommitSha := newApp.Status.Sync.Revision

		revisionHistories := newApp.Status.History
		appSourcePreiviousCommitSha := ""
		if revisionHistories != nil {
			log.Info("revisionHistories ", revisionHistories)
			log.Info("history ", len(revisionHistories))
			log.Info("previous revision: ", revisionHistories[len(revisionHistories)-1])
			appSourcePreiviousCommit := revisionHistories[len(revisionHistories)-1]
			appSourcePreiviousCommitSha = appSourcePreiviousCommit.Revision
		}

		appServer := newApp.Status.Sync.ComparedTo.Destination.Server

		err := signManifestAndGenerateProvenance(appName, appPath, appServer,
			appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, created)
		if err != nil {
			return err
		}

	}
	return nil
}

func signManifestAndGenerateProvenance(appName, appPath, appServer,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string, created bool) error {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return nil
	}

	manifestStorageType := interlaceConfig.ManifestStorageType

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	if appSourceRepoUrl == interlaceConfig.ManifestGitUrl {
		log.Info("Skipping changes in application that manages manifest signatures")
		return nil
	}

	allStorageBackEnds, err := storage.InitializeStorageBackends(appName, appPath, appDirPath,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, manifestStorageType,
	)

	if err != nil {
		log.Errorf("Error in initializing storage backends: %s", err.Error())
		return err
	}

	log.Info("manifestStorageType ", manifestStorageType)
	storageBackend := allStorageBackEnds[manifestStorageType]

	if storageBackend != nil {

		manifestGenerated := false

		loc, _ := time.LoadLocation("UTC")
		buildStartedOn := time.Now().In(loc)
		err = storageBackend.SetBuildStartedOn(buildStartedOn)
		if err != nil {
			log.Errorf("Error in setting  build start time: %s", err.Error())
			return err
		}

		if created {
			manifestGenerated, err = manifest.GenerateInitialManifest(appName, appPath, appDirPath)
			if err != nil {
				log.Errorf("Error in generating initial manifest: %s", err.Error())
				return err
			}
		} else {
			yamlBytes, err := storageBackend.GetLatestManifestContent()
			if err != nil {
				log.Errorf("Error in retriving latest manifest content: %s", err.Error())

				if storageBackend.Type() == git.StorageBackendGit {
					log.Info("Going to try generating initial manifest again")
					manifestGenerated, err = manifest.GenerateInitialManifest(appName, appPath, appDirPath)
					log.Info("manifestGenerated after generating initial manifest again: ", manifestGenerated)
					if err != nil {
						log.Errorf("Error in generating initial manifest: %s", err.Error())
						return err
					}
				} else {
					return err
				}

			}
			manifestGenerated, err = manifest.GenerateManifest(appName, appDirPath, yamlBytes)
			if err != nil {
				log.Errorf("Error in generating latest manifest: %s", err.Error())
				return err
			}
		}
		log.Info("manifestGenerated ", manifestGenerated)
		if manifestGenerated {

			err = storageBackend.StoreManifestBundle()
			if err != nil {
				log.Errorf("Error in storing latest manifest bundle(signature, prov) %s", err.Error())
				return err
			}

			buildFinishedOn := time.Now().In(loc)
			err = storageBackend.SetBuildFinishedOn(buildFinishedOn)
			if err != nil {
				log.Errorf("Error in setting  build start time: %s", err.Error())
				return err
			}
		}
	} else {

		return fmt.Errorf("Could not find storage backend")
	}

	return nil
}
