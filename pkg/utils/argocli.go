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

package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	log "github.com/sirupsen/logrus"
)

const (
	argocdCmd = "argocd"
)

// TODO: remove this function once argocd v2.4.0 is released
// It includes a bug fix for the issue https://github.com/argoproj/argo-cd/issues/9196
// As a workaround, this function uses argocd command for patch resource to avoid the issue
func ApplyResourcePatch(kind, resourceName, namespace, appName string, patchBytes []byte) error {

	err := loginArgoCDAPI()
	if err != nil {
		return err
	}

	var result bool = false
	err = retry(RETRY_ATTEMPTS, 2*time.Second, func() (res bool, err error) {
		result := patchResource(kind, resourceName, namespace, appName, patchBytes)
		return result, nil
	})

	if result == true {
		log.Info("Patching completed result: %s", result)
	}
	return nil
}

func retry(attempts int, sleep time.Duration, f func() (bool, error)) (err error) {
	for i := 0; i < attempts; i++ {
		log.Info("This is attempt number", i)
		if i > 0 {
			log.Info("retrying after error:", err)
			time.Sleep(sleep)
			sleep *= 2
		}
		res, _ := f()

		if res == true {
			break
		}
	}
	return fmt.Errorf("after %d attempts, last error: %s", attempts, err)
}

func loginArgoCDAPI() error {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return nil
	}

	argocdUser := interlaceConfig.ArgocdUser
	argocdPass := interlaceConfig.ArgocdUserPwd
	argoserver := strings.TrimPrefix(interlaceConfig.ArgocdApiBaseUrl, "https://")

	_, err = CmdExec(argocdCmd, "", "login", argoserver, "--insecure", "--username", argocdUser, "--password", argocdPass)
	if err != nil {
		log.Infof("Error in executing argocd login : %s ", err.Error())
		return err
	}
	log.Infof(" Executing argocd login succeeded")
	return nil
}

func patchResource(kind, resourceName, namespace, appName string, patchBytes []byte) bool {
	interlaceConfig, _ := config.GetInterlaceConfig()

	argoserver := strings.TrimPrefix(interlaceConfig.ArgocdApiBaseUrl, "https://")
	_, err := CmdExec(argocdCmd, "", "app", "patch-resource", appName, "--server", argoserver,
		"--kind", kind,
		"--namespace", namespace,
		"--resource-name", resourceName,
		"--patch-type", patchType,
		"--patch", string(patchBytes),
	)
	if err != nil {
		log.Infof("Error in executing argocd apply patch : %s ", err.Error())
		return false
	}
	log.Infof(" Applying argocd patches succeeded")
	return true

}
