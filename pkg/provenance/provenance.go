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

package provenance

import (
	"time"

	"github.com/IBM/argocd-interlace/pkg/application"
)

type Provenance interface {
	GenerateProvanance(appData application.ApplicationData, target, targatDigest string,
		uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error
	VerifySourceMaterial(appData application.ApplicationData) (bool, error)
}
