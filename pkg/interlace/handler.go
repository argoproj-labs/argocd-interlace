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

package interlace

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	iprof "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	iprofClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/interlaceprofile/clientset/versioned"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/manifest"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/annotation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/verify"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func CreateEventHandler(app *appv1.Application, iProfClientset iprofClientset.Interface, appProvClientset appprovClientset.Interface, interlaceNS string, kubeConfig *rest.Config) error {

	appName := app.GetName()
	profile, err := getMatchedProfile(app, iProfClientset, interlaceNS)
	if err != nil {
		return errors.Wrap(err, "failed to get InterlaceProfile which matches with the application")
	}
	if profile == nil {
		log.Info("no profiles matched with the detected Application sync. skip this time.")
		return nil
	}

	log.Infof("[%s]: Interlace detected creation of new Application resource: %s", appName, appName)

	sourceVerified := false

	appData, _ := application.NewApplicationData(app, true)

	sourceVerifySkipped := false
	sourceVerified, err = verifySourceMaterial(*appData, profile, appData.IsHelm, kubeConfig, interlaceNS)
	if err != nil {
		log.Infof("[%s]: Interlace's signature verification of Application source materials failed: %s", appName, appName)
		return err
	} else {
		if !sourceVerified {
			sourceVerifySkipped = true
		}
	}

	log.Info("sourceVerified ", sourceVerified)
	log.Info("sourceVerifySkipped ", sourceVerifySkipped)
	if sourceVerified || sourceVerifySkipped {
		log.Infof("[%s]: Interlace's signature verification of Application source materials succeeded: %s", appName, appName)

		storageBackend, err := signManifestAndGenerateProvenance(*appData, profile, true, appProvClientset, sourceVerified, sourceVerifySkipped, kubeConfig, interlaceNS)
		if err != nil {
			return err
		}
		if storageBackend != nil {
			log.Infof("[%s]: provenance data is stored in %s", appName, storageBackend.GetDestinationString())
		} else {
			log.Infof("[%s]: provenance data is nil", appName)
		}
	}

	return nil
}

// Handles update events for the Application CRD
// Triggers the following steps:
// Retrive latest manifest via ArgoCD api
// Sign manifest
// Generate provenance record
// Store signed manifest, provenance record in annotation
func UpdateEventHandler(oldApp, newApp *appv1.Application, iProfClientset iprofClientset.Interface, appProvClientset appprovClientset.Interface, interlaceNS string, kubeConfig *rest.Config) error {

	created := false
	appName := newApp.GetName()
	profile, err := getMatchedProfile(newApp, iProfClientset, interlaceNS)
	if err != nil {
		return errors.Wrap(err, "failed to get InterlaceProfile which matches with the application")
	}
	if profile == nil {
		log.Info("no profiles matched with the detected Application sync. skip this time.")
		return nil
	}

	sourceVerified := false

	log.Infof("[%s]: Interlace detected update of existing Application resource: %s", appName, appName)

	appData, _ := application.NewApplicationData(newApp, false)

	log.Infof("[%s]: Interlace detected update of an exsiting Application resource: %s", appName, appName)

	sourceVerifySkipped := false
	sourceVerified, err = verifySourceMaterial(*appData, profile, appData.IsHelm, kubeConfig, interlaceNS)
	if err != nil {
		log.Infof("[%s]: Interlace's signature verification of Application source materials failed: %s", appName, appName)
		return err
	} else {
		if !sourceVerified {
			sourceVerifySkipped = true
		}
	}

	log.Info("sourceVerified ", sourceVerified)
	log.Info("sourceVerifySkipped ", sourceVerifySkipped)
	if sourceVerified || sourceVerifySkipped {
		log.Infof("[%s]: Interlace's signature verification of Application source materials succeeded: %s", appName, appName)

		storageBackend, err := signManifestAndGenerateProvenance(*appData, profile, created, appProvClientset, sourceVerified, sourceVerifySkipped, kubeConfig, interlaceNS)
		if err != nil {
			return err
		}
		if storageBackend != nil {
			log.Infof("[%s]: provenance data is stored in %s", appName, storageBackend.GetDestinationString())
		} else {
			log.Infof("[%s]: provenance data is nil", appName)
		}
	}

	return nil
}

func ProfileEventHandler(prof *iprof.InterlaceProfile, appClientset appClientset.Interface, iProfClientset iprofClientset.Interface, appProvClientset appprovClientset.Interface, argocdNS, interlaceNS string, kubeConfig *rest.Config) error {
	// if len(prof.Spec.Protection.Generators) > 0 {
	// 	for i, appConfig := range prof.Spec.Applications {
	// 		keyConfig := appConfig.SignConfig.KeyConfig
	// 		if keyConfig.PEM == "" && keyConfig.Secret == "" {
	// 			continue
	// 		}
	// 		privkeyBytes, err := getKeyPEMFromKeyConfig(keyConfig, kubeConfig, interlaceNS)
	// 		if err != nil {
	// 			return errors.Wrap(err, "failed to get private key from profile")
	// 		}
	// 		pubkeyBytes, err := extractPubkeyFromPrivKey(privkeyBytes)
	// 		if err != nil {
	// 			return errors.Wrap(err, "failed to get public key from private key")
	// 		}
	// 		err = generateEnforceRuleForProfile(prof, i, privkeyBytes, pubkeyBytes, kubeConfig, interlaceNS)
	// 		if err != nil {
	// 			return errors.Wrap(err, "failed to generate enforce rule")
	// 		}
	// 		log.Infof("enforce rule is generated for profile \"%s\"", prof.GetName())
	// 	}

	// 	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to create a dynamic client")
	// 	}
	// 	err = generateApplicationSetForProfile(prof, dynamicClient, argocdNS)
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to generate application")
	// 	}
	// 	log.Infof("application is generated for profile \"%s\"", prof.GetName())
	// }

	appList, err := appClientset.ArgoprojV1alpha1().Applications(argocdNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "failed to list applications")
	}
	for _, app := range appList.Items {
		err = CreateEventHandler(&app, iProfClientset, appProvClientset, interlaceNS, kubeConfig)
		if err != nil {
			return errors.Wrapf(err, "failed to process application \"%s\"", app.GetName())
		}
	}
	return nil
}

func getMatchedProfile(app *appv1.Application, iProfClientset iprofClientset.Interface, interlaceNS string) (*iprof.InterlaceProfile, error) {
	iprofList, err := iProfClientset.InterlaceV1beta1().InterlaceProfiles(interlaceNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var matched *iprof.InterlaceProfile
	for i, p := range iprofList.Items {
		if !p.Match(app) {
			continue
		}
		if matched == nil {
			matched = &(iprofList.Items[i])
			break
		}
	}
	if matched == nil {
		return nil, nil
	}
	return matched, nil
}

func verifySourceMaterial(appData application.ApplicationData, profile *iprof.InterlaceProfile, isHelm bool, kubeConfig *rest.Config, interlaceNS string) (bool, error) {
	appPath := appData.AppPath
	appSourceRepoUrl := appData.AppSourceRepoUrl
	chart := appData.Chart
	targetRev := appData.AppSourceRevision
	if isHelm {
		return verify.VerifyHelmSourceMaterial(appPath, appSourceRepoUrl, chart, targetRev)
	} else {
		keyConfig := profile.Spec.VerifyConfig.KeyConfig
		if keyConfig.PEM == "" && keyConfig.Secret == "" {
			return false, nil
		}
		pubkeyBytes, err := getKeyPEMFromKeyConfig(keyConfig, kubeConfig, interlaceNS)
		if err != nil {
			return false, errors.Wrap(err, "failed to get verification key")
		}
		return verify.VerifyKustomizeSourceMaterial(appPath, appSourceRepoUrl, pubkeyBytes)
	}
}

func signManifestAndGenerateProvenance(appData application.ApplicationData, profile *iprof.InterlaceProfile, created bool, appProvClientset appprovClientset.Interface, sourceVerified, sourceVerifySkipped bool, kubeConfig *rest.Config, interlaceNS string) (storage.StorageBackend, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get interlace config")
	}

	manifestImage := appData.Object.GetAnnotations()[config.APP_MANIFEST_IMAGE_ANNOTATION_NAME]

	storageConfig := storage.StorageConfig{
		ManifestStorageType:   interlaceConfig.ManifestStorageType,
		AppData:               appData,
		Profile:               profile,
		AppProvClientset:      appProvClientset,
		InterlaceNS:           interlaceConfig.ArgocdInterlaceNamespace,
		MaxResultsInResource:  interlaceConfig.MaxResultsInResource,
		UploadTLog:            interlaceConfig.UploadTLog,
		ManifestImage:         manifestImage,
		RegistrySecret:        profile.Spec.SignConfig.RegistryConfig.Secret,
		AllowInsecureRegistry: profile.Spec.SignConfig.RegistryConfig.InsecureRegistry,
	}
	allStorageBackEnds, err := storage.InitializeStorageBackends(storageConfig, kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize output config")
	}
	storageBackend := allStorageBackEnds[interlaceConfig.ManifestStorageType]

	var provMgr provenance.ProvenanceManager
	if storageBackend != nil {

		manifestGenerated := false

		buildStartedOn := time.Now()

		log.Info("buildStartedOn:", buildStartedOn)
		var manifestBytes []byte
		if created {

			log.Infof("[%s] Interlace downloads desired manifest from ArgoCD REST API", appData.AppName)
			manifestGenerated, err = manifest.GenerateInitialManifest(appData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to initialize manifest")
			}
		} else {

			log.Infof("[%s] Interlace downloads desired manifest from ArgoCD REST API", appData.AppName)
			yamlBytes, err := storageBackend.GetLatestManifestContent()
			if err != nil {
				log.Errorf("Error in retriving latest manifest content: %s", err.Error())

				if storageBackend.Type() == annotation.StorageBackendAnnotation {
					log.Info("Going to try generating initial manifest again")
					manifestGenerated, err = manifest.GenerateInitialManifest(appData)
					log.Info("manifestGenerated after generating initial manifest again: ", manifestGenerated)
					if err != nil {
						log.Errorf("Error in generating initial manifest: %s", err.Error())
						return nil, err
					}
				} else {
					return nil, err
				}

			}
			log.Infof(": Argocd Interlace generates manifest %s", appData.AppName)
			manifestGenerated, err = manifest.GenerateManifest(appData, yamlBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to generate manifest")
			}
			manifestBytes = yamlBytes
		}
		var privkeyBytes []byte
		signKeyConfig := profile.Spec.SignConfig.KeyConfig
		if signKeyConfig.PEM != "" || signKeyConfig.Secret != "" {
			privkeyBytes, err = getKeyPEMFromKeyConfig(signKeyConfig, kubeConfig, interlaceNS)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get signing key")
			}
		}
		// select resources that will be signed from the manifest
		if manifestGenerated && len(profile.Spec.SignConfig.Match) > 0 {
			manifestBytes, err = manifest.PickUpResourcesFromManifest(appData, profile.Spec.SignConfig.Match)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get a manifest to be signed")
			}
		}
		log.Info("manifestGenerated ", manifestGenerated)
		if manifestGenerated {
			err = storageBackend.StoreManifestBundle(sourceVerified, manifestBytes, privkeyBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to save the manifest and signature")
			}
		}

		buildFinishedOn := time.Now()
		log.Info("buildFinishedOn:", buildFinishedOn)
		if manifestGenerated || interlaceConfig.AlwaysGenerateProv {
			err = storageBackend.StoreManifestProvenance(buildStartedOn, buildFinishedOn, sourceVerified, privkeyBytes)
			if err != nil {
				return nil, errors.Wrap(err, "failed to save provenance")
			}
		}

		provMgr = storageBackend.GetProvenanceManager()
	} else {
		return nil, errors.New("Could not find storage backend")
	}
	if provMgr == nil {
		log.Info("storageBackend.GetProvenance() returns nli")
	} else {
		prov := provMgr.GetProvenance()
		if len(prov.Subject) > 0 {
			subjectName := prov.Subject[0].Name
			if subjectName != "" {
				log.Infof("storageBackend.GetProvenance() returns provenance for subject `%s`", subjectName)
			}
		}
	}

	return storageBackend, nil
}

func getKeyPEMFromKeyConfig(keyConfig iprof.KeyConfig, kubeConfig *rest.Config, interlaceNS string) ([]byte, error) {
	if keyConfig.Secret == "" && keyConfig.PEM == "" {
		return nil, errors.New("key config must have either secret or PEM")
	}
	if keyConfig.PEM != "" {
		return []byte(keyConfig.PEM), nil
	}
	if keyConfig.Secret != "" {
		secret, err := utils.GetSecret(kubeConfig, interlaceNS, keyConfig.Secret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get secret")
		}
		key, ok := secret.Data["key"]
		if !ok {
			return nil, errors.New("key secret must have \"key\" in its data")
		}
		return key, nil
	}
	return nil, errors.New("failed to get key data from key config")
}

func getGitAuthInfoFromSecret(kubeConfig *rest.Config, secretName, interlaceNS string) (string, string, string, error) {
	secret, err := utils.GetSecret(kubeConfig, interlaceNS, secretName)
	if err != nil {
		return "", "", "", errors.Wrap(err, "failed to get secret")
	}
	user := secret.Data["user"]
	token := secret.Data["token"]
	email := secret.Data["email"]
	gitUser := strings.TrimSuffix(string(user), "\n")
	gitToken := strings.TrimSuffix(string(token), "\n")
	gitEmail := strings.TrimSuffix(string(email), "\n")
	return gitUser, gitToken, gitEmail, nil
}

func extractPubkeyFromPrivKey(privkeyBytes []byte) ([]byte, error) {
	passwd := utils.GetCosignPassword()
	signerVerifier, err := cosign.LoadPrivateKey(privkeyBytes, []byte(passwd))
	if err != nil {
		return nil, errors.Wrap(err, "failed to load private key")
	}
	pubkey, err := signerVerifier.PublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get public key from signerVerifier")
	}
	pubkeyASNBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal public key")
	}
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubkeyASNBytes}
	pubkeyBytes := pem.EncodeToMemory(pemBlock)
	return pubkeyBytes, nil
}
