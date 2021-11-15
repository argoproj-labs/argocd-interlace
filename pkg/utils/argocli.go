//
// Copyright 2020 IBM Corporation
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
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	log "github.com/sirupsen/logrus"
)

const (
	argocdCmd = "argocd"
)

func ApplyResourcePatch(kind, resourceName, namespace, appName string, patches []string) error {

	err := loginArgoCDAPI()
	if err != nil {
		return err
	}

	var result bool = false
	err = retry(10, 2*time.Second, func() (res bool, err error) {
		result := patchResource(kind, resourceName, namespace, appName, patches)
		return result, nil
	})

	if result == true {
		log.Info("result ->>> ", result)
		log.Info("Patching completed")
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

	argocdPwd := interlaceConfig.ArgocdPwd
	argoserver := interlaceConfig.ArgocdServer

	_, err = CmdExec(argocdCmd, "", "login", argoserver, "--insecure", "--username", "admin", "--password", argocdPwd)
	if err != nil {
		log.Infof("Error: CmdExec argocd login : %s ", err.Error())
		return err
	}
	log.Infof(" CmdExec argocd login succeeded")
	return nil
}

func patchResource(kind, resourceName, namespace, appName string, patches []string) bool {
	interlaceConfig, _ := config.GetInterlaceConfig()

	argoserver := interlaceConfig.ArgocdServer

	for _, patch := range patches {
		_, err := CmdExec(argocdCmd, "", "app", "patch-resource", appName, "--server", argoserver,
			"--kind", kind,
			"--namespace", namespace,
			"--resource-name", resourceName,
			"--patch-type", "application/merge-patch+json",
			"--patch", patch,
		)
		if err != nil {
			log.Infof("Error:   CmdExec argocd apply patch : %s ", err.Error())
			return false
		}

	}
	log.Infof(" CmdExec argocd patches succeeded")
	return true

}
