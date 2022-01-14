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

type ApplicationData struct {
	AppName                     string
	AppPath                     string
	AppDirPath                  string
	AppClusterUrl               string
	AppSourceRepoUrl            string
	AppSourceRevision           string
	AppSourceCommitSha          string
	AppSourcePreiviousCommitSha string
	Chart                       string
	IsHelm                      bool
	ValueFiles                  []string
	ReleaseName                 string
	Values                      string
	Version                     string
}

func NewApplicationData(appName, appPath, appDirPath, appClusterUrl,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha,
	chart string, isHelm bool, valueFiles []string, releaseName string,
	values string, version string) (*ApplicationData, error) {
	return &ApplicationData{
		AppName:                     appName,
		AppPath:                     appPath,
		AppDirPath:                  appDirPath,
		AppClusterUrl:               appClusterUrl,
		AppSourceRepoUrl:            appSourceRepoUrl,
		AppSourceRevision:           appSourceRevision,
		AppSourceCommitSha:          appSourceCommitSha,
		AppSourcePreiviousCommitSha: appSourcePreiviousCommitSha,
		Chart:                       chart,
		IsHelm:                      isHelm,
		ValueFiles:                  valueFiles,
		ReleaseName:                 releaseName,
		Values:                      values,
		Version:                     version,
	}, nil
}
