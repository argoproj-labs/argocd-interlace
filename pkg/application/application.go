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

package application

import (
	"path/filepath"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/gitutil"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	log "github.com/sirupsen/logrus"
)

type ApplicationData struct {
	AppName                     string
	AppNamespace                string
	AppPath                     string
	AppDirPath                  string
	AppClusterUrl               string
	AppSourceRepoUrl            string
	AppSourceRevision           string
	AppSourceCommitSha          string
	AppSourcePreiviousCommitSha string
	AppDestinationNamespace     string
	Chart                       string
	IsHelm                      bool
	ValueFiles                  []string
	ReleaseName                 string
	Values                      string
	Version                     string
	Object                      *appv1.Application
}

func NewApplicationData(app *appv1.Application, isCreate bool) (*ApplicationData, error) {
	interlaceConfig, _ := config.GetInterlaceConfig()
	appName := app.GetName()
	appNS := app.GetNamespace()
	appDestNamespace := app.Spec.Destination.Namespace

	var appClusterUrl, appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string
	if isCreate {
		appClusterUrl = app.Spec.Destination.Server
		appSourceRepoUrl = app.Spec.Source.RepoURL
		appSourceRevision = app.Spec.Source.TargetRevision
		appSourceCommitSha = ""
		appSourcePreiviousCommitSha = ""
	} else {
		appClusterUrl = app.Status.Sync.ComparedTo.Destination.Server
		appSourceRepoUrl = app.Status.Sync.ComparedTo.Source.RepoURL
		appSourceRevision = app.Status.Sync.ComparedTo.Source.TargetRevision
		appSourceCommitSha = app.Status.Sync.Revision
		revisionHistories := app.Status.History
		if revisionHistories != nil {
			log.Info("revisionHistories ", revisionHistories)
			log.Info("history ", len(revisionHistories))
			log.Info("previous revision: ", revisionHistories[len(revisionHistories)-1])
			appSourcePreiviousCommit := revisionHistories[len(revisionHistories)-1]
			appSourcePreiviousCommitSha = appSourcePreiviousCommit.Revision
		}
	}

	gitToken := argoutil.GetRepoCredentials(appSourceRepoUrl)
	// Create does not have app.Status.Sync.Revision information, we need to extract commitsha by API
	commitSha := gitutil.GitLatestCommitSha(app.Spec.Source.RepoURL, app.Spec.Source.TargetRevision, gitToken)
	if commitSha != "" {
		appSourceCommitSha = commitSha
	}
	var appPath, appDirPath, chart, releaseName, values, version string
	var valueFiles []string
	isHelm := app.Spec.Source.IsHelm()
	if isHelm {
		chart = app.Spec.Source.Chart
		valueFiles = app.Spec.Source.Helm.ValueFiles
		releaseName = app.Spec.Source.Helm.ReleaseName
		values = app.Spec.Source.Helm.Values
		version = app.Spec.Source.Helm.Version
		log.Info("len(valueFiles)", len(valueFiles))
		log.Info("releaseName", releaseName)
		log.Info("version", version)
		appPath = filepath.Join(interlaceConfig.WorkspaceDir, appName)
		appDirPath = appPath
	} else {
		chart = ""
		appPath = app.Spec.Source.Path
		appDirPath = filepath.Join(interlaceConfig.WorkspaceDir, appName, appPath)
	}

	return &ApplicationData{
		AppName:                     appName,
		AppNamespace:                appNS,
		AppPath:                     appPath,
		AppDirPath:                  appDirPath,
		AppClusterUrl:               appClusterUrl,
		AppSourceRepoUrl:            appSourceRepoUrl,
		AppSourceRevision:           appSourceRevision,
		AppSourceCommitSha:          appSourceCommitSha,
		AppSourcePreiviousCommitSha: appSourcePreiviousCommitSha,
		AppDestinationNamespace:     appDestNamespace,
		Chart:                       chart,
		IsHelm:                      isHelm,
		ValueFiles:                  valueFiles,
		ReleaseName:                 releaseName,
		Values:                      values,
		Version:                     version,
		Object:                      app,
	}, nil
}
