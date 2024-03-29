package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	appprov "github.com/argoproj-labs/argocd-interlace/pkg/apis/applicationprovenance/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/manifest"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	helmprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/helm"
	kustprov "github.com/argoproj-labs/argocd-interlace/pkg/provenance/kustomize"
	"github.com/argoproj-labs/argocd-interlace/pkg/sign"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
)

const (
	StorageBackendResource = "resource"
)

type ResourceStorageBackend struct {
	appData application.ApplicationData
	provMgr provenance.ProvenanceManager

	appProvClientset      appprovClientset.Interface
	interlaceNS           string
	maxResults            int
	uploadTLog            bool
	rekorURL              string
	manifestImage         string
	registrySecret        string
	allowInsecureRegistry bool
	kubeConfig            *rest.Config
}

func NewStorageBackend(appData application.ApplicationData, appProvClientset appprovClientset.Interface, interlaceNS string, maxResults int, uploadTLog bool, rekorURL, manifestImage string, registrySecret string, allowInsecureRegistry bool, kubeConfig *rest.Config) (*ResourceStorageBackend, error) {
	return &ResourceStorageBackend{
		appData:               appData,
		appProvClientset:      appProvClientset,
		interlaceNS:           interlaceNS,
		maxResults:            maxResults,
		uploadTLog:            uploadTLog,
		rekorURL:              rekorURL,
		manifestImage:         manifestImage,
		registrySecret:        registrySecret,
		allowInsecureRegistry: allowInsecureRegistry,
		kubeConfig:            kubeConfig,
	}, nil
}

func (s *ResourceStorageBackend) GetLatestManifestContent() ([]byte, error) {
	return nil, nil
}

func (s *ResourceStorageBackend) StoreManifestBundle(sourceVerifed bool, manifestBytes, privkeyBytes []byte) error {

	signedManifestPath := filepath.Join(s.appData.AppDirPath, config.SIGNED_MANIFEST_FILE_NAME)

	log.Debugf("manifest bytes: %s", string(manifestBytes))

	manifestFile, err := ioutil.TempFile("", "manifest.yaml")
	if err != nil {
		return errors.Wrap(err, "error in creating a temp manifest file")
	}
	defer os.Remove(manifestFile.Name())

	_, err = manifestFile.Write(manifestBytes)
	if err != nil {
		return errors.Wrap(err, "error in saving the manifest as a temp file")
	}
	manifestPath := manifestFile.Name()

	doSigning := true
	// if signing key is empty, do not sign the manifest and return here
	if string(privkeyBytes) == "" {
		log.Warnf("signing key is empty, so skip signing the manifest")
		doSigning = false
	}

	if doSigning {
		privkeyFile, err := ioutil.TempFile("", "privkey")
		if err != nil {
			return errors.Wrap(err, "error in creating a temp key file")
		}
		defer os.Remove(privkeyFile.Name())

		_, err = privkeyFile.Write(privkeyBytes)
		if err != nil {
			return errors.Wrap(err, "error in saving the signing key as a temp file")
		}

		keyPath := privkeyFile.Name()
		signedBytes, err := sign.SignManifest(keyPath, manifestPath, signedManifestPath)
		if err != nil {
			return errors.Wrap(err, "error in signing manifest")
		}
		manifestBytes = signedBytes
	}
	manifestYAMLs := k8smnfutil.SplitConcatYAMLs(manifestBytes)

	log.Info("len(manifestYAMLs): ", len(manifestYAMLs))
	interlaceConfig, err := config.GetInterlaceConfig()

	var annotations map[string]string
	for _, item := range manifestYAMLs {

		var obj unstructured.Unstructured
		err := yaml.Unmarshal(item, &obj)
		if err != nil {
			log.Errorf("Error unmarshling: %s", err.Error())
		}

		kind := obj.GetKind()
		resourceName := obj.GetName()
		namespace := obj.GetNamespace()

		resourceLabels := obj.GetLabels()

		log.Info("kind :", kind, " resourceName ", resourceName, " namespace", namespace)

		isSignatureresource := false
		log.Info("resourceLabels ", resourceLabels)

		if rscLabel, ok := resourceLabels[interlaceConfig.SignatureResourceLabel]; ok {
			isSignatureresource, err = strconv.ParseBool(rscLabel)
			if err != nil {
				log.Errorf("failed to parse label value `%s`; err: %s", rscLabel, err.Error())
			}

		}
		log.Info("isSignatureresource :", isSignatureresource)
		if isSignatureresource {
			if namespace == "" {
				namespace = s.appData.AppDestinationNamespace
			}
			log.Info("Patch kind:", kind, " name:", resourceName, " in namespace:", namespace)

			annotations = k8smnfutil.GetAnnotationsInYAML(item)

			message := "null"
			signature := "null"
			if sourceVerifed {
				message = annotations[config.MSG_ANNOTATION_NAME]
				signature = annotations[config.SIG_ANNOTATION_NAME]
			}

			patchData, err := preparePatch(message, signature, kind)
			if err != nil {
				return errors.Wrap(err, "error in creating patch for application resource config")
			}

			log.Info("len(patchData)", len(patchData))

			log.Infof("[%s] Interlace attaches signature to resource as annotation:", s.appData.AppName)

			err = argoutil.ApplyResourcePatch(kind, resourceName, namespace, s.appData.AppName, patchData)
			// err = argoutil.PatchResource(interlaceConfig.ArgocdApiBaseUrl, s.appData.AppName, namespace, resourceName, gv.Group, gv.Version, kind, patchData)

			if err != nil {
				return errors.Wrap(err, "error in patching application resource config")
			}
		}
	}

	if err != nil {
		return errors.Wrap(err, "error in getting digest")
	}

	if s.manifestImage != "" {
		secretKeychain := &utils.SecretKeyChain{
			Name:       s.registrySecret,
			Namespace:  s.interlaceNS,
			KubeConfig: s.kubeConfig,
		}
		err = utils.UploadManifestImage(manifestBytes, s.manifestImage, s.allowInsecureRegistry, secretKeychain)
		if err != nil {
			return errors.Wrap(err, "failed to upload manifest image")
		}
		err = utils.SignImage(s.manifestImage, privkeyBytes, "", s.uploadTLog, s.allowInsecureRegistry, secretKeychain)
		if err != nil {
			return errors.Wrap(err, "failed to sign the uploaded manifest image")
		}
	}
	return nil
}

func preparePatch(message, signature, kind string) ([]byte, error) {

	patchData := map[string]interface{}{}
	patchDataSub := map[string]interface{}{}
	if kind == "ConfigMap" {
		if message != "" {
			patchDataSub["message"] = message
		}
		if signature != "" {
			patchDataSub["signature"] = signature
		}
		patchData["data"] = patchDataSub
	} else {
		msgAnnot := config.MSG_ANNOTATION_NAME
		if message != "" {
			patchDataSub[msgAnnot] = message
		}
		sigAnnot := config.SIG_ANNOTATION_NAME
		if signature != "" {
			patchDataSub[sigAnnot] = signature
		}
		patchData["metadata"] = map[string]interface{}{
			"annotations": patchDataSub,
		}
	}
	return json.Marshal(patchData)
}

func (s *ResourceStorageBackend) StoreManifestProvenance(buildStartedOn time.Time, buildFinishedOn time.Time, sourceVerified bool, privkeyBytes []byte) error {
	var target, hash string
	var err error
	if s.manifestImage != "" {
		target = s.manifestImage
		hash, err = utils.GetImageHash(target)
		if err != nil {
			return errors.Wrap(err, "failed to get image digest")
		}
	} else {
		target = filepath.Join(s.appData.AppDirPath, config.MANIFEST_FILE_NAME)
		hash, err = utils.ComputeHash(target)
		if err != nil {
			return errors.Wrap(err, "failed to compute hash value of the manifest file")
		}
	}

	var provMgr provenance.ProvenanceManager
	if s.appData.IsHelm {
		provMgr, _ = helmprov.NewProvenanceManager(s.appData)
	} else {
		provMgr, _ = kustprov.NewProvenanceManager(s.appData)
	}
	err = provMgr.GenerateProvenance(target, hash, privkeyBytes, s.uploadTLog, s.rekorURL, buildStartedOn, buildFinishedOn)
	if err != nil {
		return errors.Wrap(err, "failed to generate provenance data")
	}
	s.provMgr = provMgr

	appName := s.appData.AppName
	appNamespace := s.appData.AppNamespace
	appProvName := s.appData.AppName

	prov := provMgr.GetProvenance()
	provBytes, err := json.Marshal(prov)
	if err != nil {
		return errors.Wrap(err, "failed to marshal provenance data to be stored in ApplicationProvenance")
	}

	provSig := provMgr.GetProvSignature()

	manifestBytes, err := manifest.GetManifest(s.appData)
	if err != nil {
		return errors.Wrap(err, "failed to get the generated manifest to be stored in ApplicationProvenance")
	}

	appProvExists := false
	current, err := s.appProvClientset.InterlaceV1beta1().ApplicationProvenances(s.interlaceNS).Get(context.TODO(), appProvName, metav1.GetOptions{})
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return errors.Wrap(err, fmt.Sprintf("failed to get %s", appProvName))
		}
	} else {
		appProvExists = true
	}

	var newone *appprov.ApplicationProvenance
	doneMsg := "created"
	now := metav1.NewTime(time.Now().UTC())
	if appProvExists {
		newone = current
		newResults := current.Status.Results
		if newResults == nil {
			newResults = []appprov.ResultPerSync{}
		}
		newResult := appprov.ResultPerSync{
			Time:           now,
			SourceVerified: sourceVerified,
			Manifest:       manifestBytes,
			Provenance:     provBytes,
			Signature:      provSig,
		}
		newResults = append(newResults, newResult)
		startIndex := 0
		// if the number of the results exceeds the max, keep the newer ones
		if len(newResults) > s.maxResults {
			startIndex = len(newResults) - s.maxResults
		}
		newone.Status = appprov.ApplicationProvenanceStatus{
			LastUpdated: now,
			Results:     newResults[startIndex:],
		}
		_, err = s.appProvClientset.InterlaceV1beta1().ApplicationProvenances(s.interlaceNS).Update(context.TODO(), newone, metav1.UpdateOptions{})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to update ApplicationProvenance `%s`", appProvName))
		}
		doneMsg = "updated"
	} else {
		newone = &appprov.ApplicationProvenance{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: s.interlaceNS,
				Name:      appProvName,
			},
			Spec: appprov.ApplicationProvenanceSpec{
				Application: appprov.ApplicationRef{
					Namespace: appNamespace,
					Name:      appName,
				},
			},
			Status: appprov.ApplicationProvenanceStatus{
				LastUpdated: now,
				Results: []appprov.ResultPerSync{
					{
						Time:           now,
						SourceVerified: sourceVerified,
						Manifest:       manifestBytes,
						Provenance:     provBytes,
						Signature:      provSig,
					},
				},
			},
		}
		_, err = s.appProvClientset.InterlaceV1beta1().ApplicationProvenances(s.interlaceNS).Create(context.TODO(), newone, metav1.CreateOptions{})
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to create ApplicationProvenance `%s`", appProvName))
		}
	}
	log.Infof("ApplicationProvenance `%s` is %s", appProvName, doneMsg)

	return nil
}

func (b *ResourceStorageBackend) UploadTLogEnabled() bool {
	return b.uploadTLog
}

func (b *ResourceStorageBackend) GetDestinationString() string {
	return fmt.Sprintf("ApplicationProvenance `%s`", b.appData.AppName)
}

func (b *ResourceStorageBackend) GetProvenanceManager() provenance.ProvenanceManager {
	return b.provMgr
}

func (b *ResourceStorageBackend) Type() string {
	return StorageBackendResource
}
