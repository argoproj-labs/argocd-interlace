package manifest

import (
	"github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

func GenerateInitialManifest(appName, appPath, appDirPath string) (bool, error) {

	// Retrive the desired state of manifest via argocd API call
	desiredManifest := utils.RetriveDesiredManifest(appName)

	items := gjson.Get(desiredManifest, "items")

	finalManifest := ""

	log.Debug("len(items.Array()) ", len(items.Array()))

	for i, item := range items.Array() {

		targetState := gjson.Get(item.String(), "targetState").String()

		finalManifest = utils.PrepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)
	}
	if finalManifest != "" {

		utils.WriteToFile(string(finalManifest), appDirPath, utils.MANIFEST_FILE_NAME)

		return true, nil
	}

	return false, nil
}

func GenerateManifest(appName, appDirPath string, yamlBytes []byte) (bool, error) {

	diffCount := 0
	finalManifest := ""

	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(yamlBytes)

	// Retrive the desired state of manifest via argocd API call
	desiredManifest := utils.RetriveDesiredManifest(appName)

	items := gjson.Get(desiredManifest, "items")

	log.Debug("len(items.Array()) ", len(items.Array()))

	// For each resource in desired manifest
	// Check if it has changed from the version that exist in the bundle manifest
	for i, item := range items.Array() {
		targetState := gjson.Get(item.String(), "targetState").String()
		if diffCount == 0 {
			diffExist := checkDiff([]byte(targetState), manifestYAMLs)
			if diffExist {
				diffCount += 1
			}
		}
		// Add desired state of each resource to finalManifest
		finalManifest = utils.PrepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)

	}

	if finalManifest != "" {
		utils.WriteToFile(string(finalManifest), appDirPath, utils.MANIFEST_FILE_NAME)

		return true, nil
	}

	return false, nil
}

func checkDiff(targetObjYAMLBytes []byte, manifestYAMLs [][]byte) bool {

	objNode, err := mapnode.NewFromBytes(targetObjYAMLBytes) // json

	log.Debug("targetObjYAMLBytes ", string(targetObjYAMLBytes))

	if err != nil {
		log.Fatalf("objNode error from NewFromYamlBytes %s", err.Error())
		// do somthing
	}

	found := false
	for _, manifest := range manifestYAMLs {

		mnfNode, err := mapnode.NewFromYamlBytes(manifest)
		if err != nil {
			log.Fatalf("mnfNode error from NewFromYamlBytes %s", err.Error())
			// do somthing
		}
		diffs := objNode.Diff(mnfNode)

		// when diffs == nil,  there is no difference in YAMLs being compared.
		if diffs == nil || diffs.Size() == 0 {
			found = true
			break
		}
	}
	return found

}
