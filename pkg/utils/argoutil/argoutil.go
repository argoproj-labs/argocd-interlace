package argoutil

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient"
	"github.com/argoproj/argo-cd/v2/pkg/apiclient/application"
	argoio "github.com/argoproj/argo-cd/v2/util/io"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const patchType = "application/merge-patch+json"

const (
	argocdCmd = "argocd"
	maxRetry  = 10
)

// TODO: remove this function once argocd v2.4.0 is released
// argocd v2.4.0 includes a bug fix for the issue https://github.com/argoproj/argo-cd/issues/9196
// As a workaround, this function uses argocd command for patch resource to avoid the issue
func ApplyResourcePatch(kind, resourceName, namespace, appName string, patchBytes []byte) error {

	err := loginArgoCDAPI()
	if err != nil {
		return err
	}

	var result bool = false
	err = retry(maxRetry, 2*time.Second, func() (res bool, err error) {
		result := patchResource(kind, resourceName, namespace, appName, patchBytes)
		return result, nil
	})
	if err != nil {
		return err
	}

	if result {
		log.Infof("Patching completed result: %v", result)
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

		if res {
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

	argocdUser := interlaceConfig.ArgocdAPIUser
	argocdPass := interlaceConfig.ArgocdAPIPass
	argoserver := strings.TrimPrefix(interlaceConfig.ArgocdAPIBaseUrl, "https://")

	_, err = utils.CmdExec(argocdCmd, "", "login", argoserver, "--insecure", "--username", argocdUser, "--password", argocdPass)
	if err != nil {
		log.Infof("Error in executing argocd login : %s ", err.Error())
		return err
	}
	log.Infof(" Executing argocd login succeeded")
	return nil
}

func patchResource(kind, resourceName, namespace, appName string, patchBytes []byte) bool {
	interlaceConfig, _ := config.GetInterlaceConfig()

	argoserver := strings.TrimPrefix(interlaceConfig.ArgocdAPIBaseUrl, "https://")
	_, err := utils.CmdExec(argocdCmd, "", "app", "patch-resource", appName, "--server", argoserver,
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

func QueryAPI(url, requestType, bearerToken string, data map[string]interface{}) (string, error) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	bearer := ""
	if bearerToken != "" {
		bearer = "Bearer " + bearerToken
	}

	var dataJson []byte
	if data != nil {
		dataJson, _ = json.Marshal(data)
	} else {
		dataJson = nil
	}
	req, err := http.NewRequest(requestType, url, bytes.NewBuffer(dataJson))
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	if bearer != "" {
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error %s", err.Error())
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	return string([]byte(body)), nil
}

func RetriveDesiredManifest(appName string) ([]string, error) {
	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
	}

	baseUrl := interlaceConfig.ArgocdAPIBaseUrl
	manifestsAPIURL := fmt.Sprintf("%s/api/v1/applications/%s/manifests", baseUrl, appName)

	token, err := GetArgoCDUserToken(interlaceConfig.ArgocdAPIBaseUrl, interlaceConfig.ArgocdAPIUser, interlaceConfig.ArgocdAPIPass)
	if err != nil {
		return nil, errors.Wrap(err, "error when getting argocd user token")
	}
	manifestsResponse, err := QueryAPI(manifestsAPIURL, "GET", token, nil)
	if err != nil {
		return nil, errors.Wrap(err, "error occured while querying argocd REST API")
	}

	var respMap map[string]interface{}
	err = json.Unmarshal([]byte(manifestsResponse), &respMap)
	if err != nil {
		return nil, errors.Wrap(err, "error occured while marshaling the manifest API response")
	}

	var manifestsIf interface{}
	var manifestsIfList []interface{}
	var manifests []string
	var ok bool
	if manifestsIf, ok = respMap["manifests"]; !ok {
		return nil, errors.New("`manifests` is not found in the manifest API response")
	}
	if manifestsIfList, ok = manifestsIf.([]interface{}); !ok {
		return nil, fmt.Errorf("expect `[]interface{}` for manifests, but got `%T`", manifestsIf)
	}
	for _, manifestIf := range manifestsIfList {
		if tmpMnf, ok := manifestIf.(string); !ok {
			log.Errorf("expect `string` in the manifest list, but got `%T`", manifestIf)
		} else {
			manifests = append(manifests, tmpMnf)
		}
	}
	return manifests, nil
}

func GetArgoCDUserToken(apiBaseURL, argocdUser, argocdUserPass string) (string, error) {
	sessionURL := fmt.Sprintf("%s/api/v1/session", apiBaseURL)
	input := map[string]interface{}{
		"username": argocdUser,
		"password": argocdUserPass,
	}
	sessiondata, err := QueryAPI(sessionURL, "POST", "", input)
	if err != nil {
		return "", err
	}
	log.Debugf("sessiondata from argocd api: %s", string(sessiondata))
	var output map[string]interface{}
	err = json.Unmarshal([]byte(sessiondata), &output)
	if err != nil {
		return "", err
	}
	sessionTokenIf, ok := output["token"]
	if !ok {
		return "", errors.New("argocd user token is not found in the response from the session api")
	}
	sessionToken, ok := sessionTokenIf.(string)
	if !ok {
		return "", fmt.Errorf("the token returned from the session api was not a string, but %T", sessionTokenIf)
	}
	return sessionToken, nil
}

func PatchResource(apiBaseURL, appName, namespace, resourceName, group, version, kind string, patchBytes []byte) error {
	opt := &apiclient.ClientOptions{
		ServerAddr: apiBaseURL,
		Insecure:   true,
		GRPCWeb:    true,
	}
	client, err := apiclient.NewClient(opt)
	if err != nil {
		return errors.Wrap(err, "failed to initialize argocd client set")
	}
	conn, appClient, err := client.NewApplicationClient()
	if err != nil {
		return errors.Wrap(err, "failed to initialize argocd application client")
	}
	defer argoio.Close(conn)

	resourcePatchRequest := &application.ApplicationResourcePatchRequest{
		Name:         &appName,
		Namespace:    namespace,
		ResourceName: resourceName,
		Group:        group,
		Version:      version,
		Kind:         kind,
		Patch:        string(patchBytes),
		PatchType:    patchType,
	}
	resourcePatchResp, err := appClient.PatchResource(context.Background(), resourcePatchRequest)
	if err != nil {
		return errors.Wrap(err, "failed to patch resource")
	}
	log.Debugf("patch resource response: %s", resourcePatchResp.Manifest)
	return nil
}
