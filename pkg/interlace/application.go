package interlace

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gajananan/argocd-interlace/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func createApplication(appName, appPath, server string) string {

	repoUrl := os.Getenv("MANIFEST_GITREPO_URL")
	targetRevision := os.Getenv("MANIFEST_GITREPO_TARGET_REVISION")
	argocdProj := os.Getenv("MANIFEST_GITREPO_ARGO_PROJECT") //"default"
	destNamespace := os.Getenv("MANIFEST_GITREPO_TARGET_NS") //"default"
	suffix := os.Getenv("MANIFEST_GITREPO_SUFFIX")
	manifestSigAppName := appName + suffix
	argocdNs := "argocd"

	path := filepath.Join(appName, appPath)

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      manifestSigAppName,
			"namespace": argocdNs,
		},
		"spec": map[string]interface{}{
			"destination": map[string]interface{}{
				"namespace": destNamespace,
				"server":    server,
			},
			"source": map[string]interface{}{
				"path":           path,
				"repoURL":        repoUrl,
				"targetRevision": targetRevision,
			},
			"syncPolicy": map[string]interface{}{
				"automated": map[string]interface{}{
					"prune":    true,
					"selfHeal": true,
				},
			},
			"project": argocdProj,
		},
	}

	baseUrl := os.Getenv("ARGOCD_API_BASE_URL")

	if baseUrl == "" {
		log.Info("ARGOCD_API_BASE_URL is empty, please specify it in configuration!")
		return ""
	}

	desiredUrl := fmt.Sprintf("%s?upsert=true&validate=true", baseUrl)

	response := utils.QueryAPI(desiredUrl, "POST", data)

	return response
}

func updateApplication(appName, appPath, server string) string {

	repoUrl := os.Getenv("MANIFEST_GITREPO_URL")
	targetRevision := os.Getenv("MANIFEST_GITREPO_TARGET_REVISION")
	argocdProj := os.Getenv("MANIFEST_GITREPO_ARGO_PROJECT") //"default"
	destNamespace := os.Getenv("MANIFEST_GITREPO_TARGET_NS") //"default"
	suffix := os.Getenv("MANIFEST_GITREPO_SUFFIX")
	manifestSigAppName := appName + suffix
	argocdNs := "argocd"

	path := filepath.Join(appName, appPath)

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      manifestSigAppName,
			"namespace": argocdNs,
		},
		"spec": map[string]interface{}{
			"destination": map[string]interface{}{
				"namespace": destNamespace,
				"server":    server,
			},
			"source": map[string]interface{}{
				"path":           path,
				"repoURL":        repoUrl,
				"targetRevision": targetRevision,
			},
			"syncPolicy": map[string]interface{}{
				"automated": map[string]interface{}{
					"prune":    true,
					"selfHeal": true,
				},
			},
			"project": argocdProj,
		},
	}
	baseUrl := os.Getenv("ARGOCD_API_BASE_URL")

	if baseUrl == "" {
		log.Info("ARGOCD_API_BASE_URL is empty, please specify it in configuration!")
		return ""
	}

	desiredUrl := fmt.Sprintf("%s/%s", baseUrl, manifestSigAppName)

	response := utils.QueryAPI(desiredUrl, "POST", data)

	return response
}

func listApplication(appName string) string {
	suffix := os.Getenv("MANIFEST_GITREPO_SUFFIX")
	manifestSigAppName := appName + suffix
	baseUrl := os.Getenv("ARGOCD_API_BASE_URL")

	if baseUrl == "" {
		log.Info("ARGOCD_API_BASE_URL is empty, please specify it in configuration!")
		return ""
	}

	desiredUrl := fmt.Sprintf("%s/%s", baseUrl, manifestSigAppName)

	response := utils.QueryAPI(desiredUrl, "GET", nil)

	return response
}
