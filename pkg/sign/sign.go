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

package sign

import (
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
)

func SignManifest(keyPath, manifestPath, signedManifestPath string) ([]byte, error) {

	so := &k8smanifest.SignOption{
		KeyPath:          keyPath,
		Output:           signedManifestPath,
		UpdateAnnotation: true,
		ImageAnnotations: nil,
	}

	signedBytes, err := k8smanifest.Sign(manifestPath, so)
	if err != nil {
		log.Errorf("Error in signing artifact: %s", err.Error())
		return nil, err
	}
	return signedBytes, nil
}
