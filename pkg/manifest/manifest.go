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

package manifest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	iprof "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	gyaml "github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func GenerateInitialManifest(appData application.ApplicationData) (bool, error) {

	appName := appData.AppName

	appDirPath := appData.AppDirPath

	// Retrive the desired state of manifest via argocd API call
	desiredManifests, err := argoutil.RetriveDesiredManifest(appName)
	if err != nil {
		log.Errorf("Error in retriving desired manifest : %s", err.Error())
		return false, err
	}

	finalManifest := ""
	for i, targetState := range desiredManifests {
		finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(desiredManifests)-1)
	}

	if finalManifest != "" {
		err := utils.WriteToFile(string(finalManifest), appDirPath, config.MANIFEST_FILE_NAME)
		if err != nil {
			log.Errorf("Error in writing manifest to file: %s", err.Error())
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func GenerateManifest(appData application.ApplicationData, yamlBytes []byte) (bool, error) {

	diffCount := 0
	finalManifest := ""

	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(yamlBytes)

	// Retrive the desired state of manifest via argocd API call
	desiredManifests, err := argoutil.RetriveDesiredManifest(appData.AppName)
	if err != nil {
		log.Errorf("Error in retriving desired manifest : %s", err.Error())
		return false, err
	}

	// For each resource in desired manifest
	// Check if it has changed from the version that exist in the bundle manifest
	for i, targetState := range desiredManifests {
		if diffCount == 0 {
			diffExist, err := checkDiff([]byte(targetState), manifestYAMLs)
			if err != nil {
				return false, err
			}
			if diffExist {
				diffCount += 1
			}
		}
		// Add desired state of each resource to finalManifest
		finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(desiredManifests)-1)

	}

	if finalManifest != "" {
		err := utils.WriteToFile(string(finalManifest), appData.AppDirPath, config.MANIFEST_FILE_NAME)
		if err != nil {
			log.Errorf("Error in writing manifest to file: %s", err.Error())
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func PickUpResourcesFromManifest(appData application.ApplicationData, matchConditions []iprof.ResourceMatchPattern) ([]byte, error) {
	manifestBytes, err := GetManifest(appData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the generated manifest")
	}
	if len(matchConditions) == 0 {
		return manifestBytes, nil
	}
	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(manifestBytes)
	matchedYAMLs := [][]byte{}
	for _, yaml := range manifestYAMLs {
		var obj *unstructured.Unstructured
		err = gyaml.Unmarshal(yaml, &obj)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the generated manifest into *unstructured.Unstructured")
		}
		for _, matchCondition := range matchConditions {
			if matchCondition.Match(obj) {
				matchedYAMLs = append(matchedYAMLs, yaml)
			}
		}
	}
	pickedYAMLs := k8smnfutil.ConcatenateYAMLs(matchedYAMLs)
	return pickedYAMLs, nil
}

func GetManifest(appData application.ApplicationData) ([]byte, error) {
	fpath := filepath.Join(appData.AppDirPath, config.MANIFEST_FILE_NAME)
	return ioutil.ReadFile(fpath)
}

func checkDiff(targetObjYAMLBytes []byte, manifestYAMLs [][]byte) (bool, error) {

	objNode, err := mapnode.NewFromBytes(targetObjYAMLBytes) // json

	if err != nil {
		log.Errorf("objNode error from NewFromYamlBytes %s", err.Error())
		return false, err

	}

	found := false
	for _, manifest := range manifestYAMLs {

		mnfNode, err := mapnode.NewFromYamlBytes(manifest)
		if err != nil {
			log.Errorf("mnfNode error from NewFromYamlBytes %s", err.Error())
			return false, err

		}

		diffs := objNode.Diff(mnfNode)

		// when diffs == nil,  there is no difference in YAMLs being compared.
		if diffs == nil || diffs.Size() == 0 {
			found = true
			break
		}
	}
	return found, nil

}

func prepareFinalManifest(targetState, finalManifest string, counter int, numberOfitems int) string {

	var obj *unstructured.Unstructured

	err := json.Unmarshal([]byte(targetState), &obj)
	if err != nil {
		log.Infof("Error in unmarshaling err %s", err.Error())
	}

	objBytes, _ := yaml.Marshal(obj)
	endLine := ""
	if !strings.HasSuffix(string(objBytes), "\n") {
		endLine = "\n"
	}

	finalManifest = fmt.Sprintf("%s%s%s", finalManifest, string(objBytes), endLine)
	finalManifest = strings.ReplaceAll(finalManifest, "object:\n", "")

	if counter < numberOfitems {
		finalManifest = fmt.Sprintf("%s---\n", finalManifest)
	}

	return finalManifest
}
