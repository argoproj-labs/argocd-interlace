package config

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/sirupsen/logrus"
)

const (
	defaultUsername = "admin"
)

const (
	MANIFEST_FILE_NAME        = "manifest.yaml"
	MANIFEST_DIR              = "manifest-bundles"
	SIGNED_MANIFEST_FILE_NAME = "manifest.signed"
	PROVENANCE_FILE_NAME      = "provenance.yaml"
	ATTESTATION_FILE_NAME     = "attestation.json"
	SIG_ANNOTATION_NAME       = "cosign.sigstore.dev/signature"
	MSG_ANNOTATION_NAME       = "cosign.sigstore.dev/message"
	CRT_ANNOTATION_NAME       = "cosign.sigstore.dev/certificate"
	BDL_ANNOTATION_NAME       = "cosign.sigstore.dev/bundle"
)

type InterlaceConfig struct {
	LogLevel                 string
	ManifestStorageType      string
	ArgocdNamespace          string
	ArgocdInterlaceNamespace string
	ArgocdAPIBaseUrl         string
	ArgocdServer             string
	ArgocdAPIUser            string
	ArgocdAPIPass            string
	UploadTLog               bool
	RekorServer              string
	RekorTmpDir              string
	ManifestAppSetMode       string
	ManifestArgocdProj       string
	ManifestSuffix           string
	SourceMaterialHashList   string
	SourceMaterialSignature  string
	AlwaysGenerateProv       bool
	SignatureResourceLabel   string
	MaxResultsInResource     int
	WorkspaceDir             string
}

var instance *InterlaceConfig

func GetInterlaceConfig() (*InterlaceConfig, error) {
	var err error
	if instance == nil {
		instance, err = newConfig()
		if err != nil {
			log.Errorf("Error in loading config: %s", err.Error())
			return nil, err
		}
	}
	return instance, nil
}

func newConfig() (*InterlaceConfig, error) {
	logLevel := os.Getenv("ARGOCD_INTERLACE_LOG_LEVEL")

	manifestStorageType := os.Getenv("MANIFEST_STORAGE_TYPE")
	if manifestStorageType == "" {
		return nil, errors.New("MANIFEST_STORAGE_TYPE is empty, please specify in configuration !")
	}

	argocdNamespace := os.Getenv("ARGOCD_NAMESPACE")
	if argocdNamespace == "" {
		return nil, errors.New("ARGOCD_NAMESPACE is empty, please specify in configuration !")
	}

	argocdInterlaceNamespace := os.Getenv("ARGOCD_INTERLACE_NAMESPACE")
	if argocdInterlaceNamespace == "" {
		return nil, errors.New("ARGOCD_INTERLACE_NAMESPACE is empty, please specify in configuration !")
	}

	argocdServerServiceName := os.Getenv("ARGOCD_SERVER_SERVICE_NAME")
	if argocdServerServiceName == "" {
		return nil, errors.New("ARGOCD_SERVER_SERVICE_NAME is empty, please specify in configuration !")
	}
	argocdAPIBaseUrl := fmt.Sprintf("https://%s.%s.svc.cluster.local", argocdServerServiceName, argocdNamespace)

	argocdUserSecretName := os.Getenv("ARGOCD_USER_SECRET_NAME")
	if argocdUserSecretName == "" {
		return nil, errors.New("ARGOCD_USER_SECRET_NAME is empty, please specify in configuration !")
	}

	argocdUserSecretPassfield := os.Getenv("ARGOCD_USER_SECRET_PASSFIELD")
	if argocdUserSecretPassfield == "" {
		return nil, errors.New("ARGOCD_USER_SECRET_PASSFIELD is empty, please specify in configuration !")
	}

	argocdAPIUsername, argocdAPIPassword, err := getArgoCDAPIUserInfoFromSecret(argocdNamespace, argocdUserSecretName, argocdUserSecretPassfield)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get argocd api username and passowrd")
	}

	sourceHashList := os.Getenv("SOURCE_MATERIAL_HASH_LIST")
	if sourceHashList == "" {
		return nil, errors.New("SOURCE_MATERIAL_HASH_LIST is empty, please specify in configuration !")
	}

	sourceHashSignature := os.Getenv("SOURCE_MATERIAL_SIGNATURE")
	if sourceHashSignature == "" {
		return nil, errors.New("SOURCE_MATERIAL_SIGNATURE is empty, please specify in configuration !")
	}

	alwaysGenerateProv := os.Getenv("ALWAYS_GENERATE_PROV")
	if alwaysGenerateProv == "" {
		return nil, errors.New("ALWAYS_GENERATE_PROV is empty, please specify in configuration !")
	}
	alwayGenProv, _ := strconv.ParseBool(alwaysGenerateProv)

	signRscLabel := os.Getenv("SIGNATURE_RSC_LABEL")
	if signRscLabel == "" {
		return nil, errors.New("SIGNATURE_RSC_LABEL is empty, please specify in configuration !")
	}

	maxResultsInResourceStr := os.Getenv("MAX_RESULTS_IN_RESOURCE")
	maxResultsInResource, err := strconv.ParseInt(maxResultsInResourceStr, 10, 64)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse value of MAX_RESULTS_IN_RESOURCE")
	}

	workspaceDir, err := ioutil.TempDir("", "workspace")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a workspace directory")
	}

	config := &InterlaceConfig{
		LogLevel:                 logLevel,
		ManifestStorageType:      manifestStorageType,
		ArgocdNamespace:          argocdNamespace,
		ArgocdInterlaceNamespace: argocdInterlaceNamespace,
		ArgocdAPIBaseUrl:         argocdAPIBaseUrl,
		ArgocdAPIUser:            argocdAPIUsername,
		ArgocdAPIPass:            argocdAPIPassword,
		SourceMaterialHashList:   sourceHashList,
		SourceMaterialSignature:  sourceHashSignature,
		AlwaysGenerateProv:       alwayGenProv,
		SignatureResourceLabel:   signRscLabel,
		MaxResultsInResource:     int(maxResultsInResource),
		WorkspaceDir:             workspaceDir,
	}

	uploadTLogStr := os.Getenv("UPLOAD_TLOG")
	uploadTLog, _ := strconv.ParseBool(uploadTLogStr)
	rekorServer := os.Getenv("REKOR_SERVER")
	if rekorServer == "" {
		return nil, errors.New("REKOR_SERVER is empty, please specify in configuration !")
	}
	config.UploadTLog = uploadTLog
	config.RekorServer = rekorServer
	config.RekorTmpDir = os.Getenv("REKORTMPDIR")
	return config, nil
}

func getArgoCDAPIUserInfoFromSecret(argocdNS, secretName, passfield string) (string, string, error) {
	clientset, _, err := utils.GetK8sClient("")
	if err != nil {
		return "", "", errors.Wrap(err, "failed to get kubernetes client")
	}
	argoSecretList, err := clientset.CoreV1().Secrets(argocdNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return "", "", errors.Wrap(err, "failed to list argocd secret")
	}
	found := false
	var userSecret corev1.Secret
	for _, s := range argoSecretList.Items {
		if s.GetName() == secretName {
			userSecret = s
			found = true
			break
		}
	}
	if !found {
		return "", "", fmt.Errorf("failed to find the argocd user secret `%s` in the namespace `%s`", secretName, argocdNS)
	}
	username := defaultUsername
	data := userSecret.Data
	if passwordBytes, ok := data[passfield]; ok {
		return username, string(passwordBytes), nil
	} else {
		return "", "", fmt.Errorf("failed to find argocd user password in the secret `%s`", userSecret.GetName())
	}
}
