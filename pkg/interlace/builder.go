package interlace

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/gajananan/argocd-interlace/pkg/manifest"
	"github.com/gajananan/argocd-interlace/pkg/storage"
	"github.com/gajananan/argocd-interlace/pkg/storage/git"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func UpdateEventHandler(oldApp, newApp *appv1.Application) {

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
		appServer := newApp.Status.Sync.ComparedTo.Destination.Server

		signManifestAndGenerateProvenance(appName, appPath, appServer,
			appSourceRepoUrl, appSourceRevision, appSourceCommitSha, created,
		)

	}

}

func signManifestAndGenerateProvenance(appName, appPath, appServer,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha string, created bool) {

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	manifestGitUrl := os.Getenv("MANIFEST_GITREPO_URL")

	if manifestGitUrl == "" {
		log.Info("MANIFEST_GITREPO_URL is empty, please specify in configuration !")
	}

	manifestGitUserId := os.Getenv("MANIFEST_GITREPO_USER")

	if manifestGitUserId == "" {
		log.Info("MANIFEST_GITREPO_USER is empty, please specify in configuration !")

	}
	manifestGitUserEmail := os.Getenv("MANIFEST_GITREPO_USEREMAIL")

	if manifestGitUserEmail == "" {
		log.Info("MANIFEST_GITREPO_USEREMAIL is empty, please specify in configuration !")
	}
	manifestGitToken := os.Getenv("MANIFEST_GITREPO_TOKEN")

	if manifestGitToken == "" {
		log.Info("MANIFEST_GITREPO_TOKEN is empty, please specify in configuration !")
	}

	log.Info("calling InitializeStorageBackends")

	allStorage, err := storage.InitializeStorageBackends(appName, appPath, appDirPath,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
		manifestGitUrl, manifestGitUserId, manifestGitUserEmail, manifestGitToken,
	)

	if err != nil {
		return
	}

	for _, storage := range allStorage {

		manifestGenerated := false

		loc, _ := time.LoadLocation("UTC")
		buildStartedOn := time.Now().In(loc)
		storage.SetBuildStartedOn(buildStartedOn)

		if created {
			manifestGenerated, err = manifest.GenerateInitialManifest(appName, appPath, appDirPath)
			if err != nil {
				log.Info("Error in initial manifest")
				continue
			}
		} else {
			yamlBytes, err := storage.GetLatestManifestContent()
			if err != nil {
				log.Info("Error in  latest manifest")
				continue
			}
			manifestGenerated, err = manifest.GenerateManifest(appName, appDirPath, yamlBytes)
		}

		if manifestGenerated {

			storage.StoreManifestSignature()

			if storage.Type() == git.StorageBackendGit {

				response := listApplication(appName)

				if strings.Contains(response, "not found") {
					createApplication(appName, appPath, appServer)
				} else {
					updateApplication(appName, appPath, appServer)
				}

			}
			buildFinishedOn := time.Now().In(loc)
			storage.SetBuildFinishedOn(buildFinishedOn)

			storage.StoreManifestProvenance()
		}
	}

	return
}
