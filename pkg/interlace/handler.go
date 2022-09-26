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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"time"

	iprof "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	iprofClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/interlaceprofile/clientset/versioned"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/enforce"
	"github.com/argoproj-labs/argocd-interlace/pkg/manifest"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/annotation"
	"github.com/argoproj-labs/argocd-interlace/pkg/storage/repository"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/gitutil"
	"github.com/argoproj-labs/argocd-interlace/pkg/verify"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appsetv1 "github.com/argoproj/argo-cd/v2/pkg/apis/applicationset/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	log "github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func CreateEventHandler(app *appv1.Application, iProfClientset iprofClientset.Interface, appProvClientset appprovClientset.Interface, interlaceNS string, kubeConfig *rest.Config) error {

	appName := app.GetName()
	appNS := app.GetNamespace()
	appClusterUrl := app.Spec.Destination.Server

	profile, err := getMatchedProfile(iProfClientset, appNS, appName, interlaceNS)
	if err != nil {
		return errors.Wrap(err, "failed to get InterlaceProfile which matches with the application")
	}
	if profile == nil {
		log.Info("no profiles matched with the detected Application sync. skip this time.")
		return nil
	}

	// Do not use app.Status  in create event.
	appSourceRepoUrl := app.Spec.Source.RepoURL
	appSourceRevision := app.Spec.Source.TargetRevision
	appSourceCommitSha := ""

	gitToken := argoutil.GetRepoCredentials(appSourceRepoUrl)
	// Create does not have app.Status.Sync.Revision information, we need to extract commitsha by API
	commitSha := gitutil.GitLatestCommitSha(app.Spec.Source.RepoURL, app.Spec.Source.TargetRevision, gitToken)
	if commitSha != "" {
		appSourceCommitSha = commitSha
	}

	interlaceConfig, _ := config.GetInterlaceConfig()

	log.Infof("[%s]: Interlace detected creation of new Application resource: %s", appName, appName)
	appPath := ""
	appDirPath := ""
	var valueFiles []string
	var releaseName string
	var values string
	var version string
	isHelm := app.Spec.Source.IsHelm()
	if isHelm {
		appPath = filepath.Join(interlaceConfig.WorkspaceDir, appName)
		appDirPath = appPath

		//ValuesFiles is a list of Helm value files to use when generating a template
		valueFiles = app.Spec.Source.Helm.ValueFiles
		releaseName = app.Spec.Source.Helm.ReleaseName
		values = app.Spec.Source.Helm.Values
		version = app.Spec.Source.Helm.Version
		log.Info("len(valueFiles)", len(valueFiles))
		log.Info("releaseName", releaseName)
		log.Info("version", version)

	} else {
		appPath = app.Spec.Source.Path
		appDirPath = filepath.Join(interlaceConfig.WorkspaceDir, appName, appPath)

	}

	appSourcePreiviousCommitSha := ""
	sourceVerified := false
	appDestNamespace := app.Spec.Destination.Namespace

	chart := app.Spec.Source.Chart
	appData, _ := application.NewApplicationData(appName, appNS, appPath, appDirPath, appClusterUrl,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha,
		appDestNamespace, chart, isHelm, valueFiles, releaseName, values, version)

	sourceVerifySkipped := false
	sourceVerified, err = verifySourceMaterial(*appData, profile, isHelm, kubeConfig, interlaceNS)
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
	interlaceConfig, _ := config.GetInterlaceConfig()
	appName := newApp.GetName()
	appNS := newApp.GetNamespace()
	appPath := newApp.Status.Sync.ComparedTo.Source.Path
	appSourceRepoUrl := newApp.Status.Sync.ComparedTo.Source.RepoURL
	appSourceRevision := newApp.Status.Sync.ComparedTo.Source.TargetRevision
	appSourceCommitSha := newApp.Status.Sync.Revision
	appDestNamespace := newApp.Spec.Destination.Namespace
	appClusterUrl := newApp.Status.Sync.ComparedTo.Destination.Server
	revisionHistories := newApp.Status.History
	appSourcePreiviousCommitSha := ""
	if revisionHistories != nil {
		log.Info("revisionHistories ", revisionHistories)
		log.Info("history ", len(revisionHistories))
		log.Info("previous revision: ", revisionHistories[len(revisionHistories)-1])
		appSourcePreiviousCommit := revisionHistories[len(revisionHistories)-1]
		appSourcePreiviousCommitSha = appSourcePreiviousCommit.Revision
	}

	profile, err := getMatchedProfile(iProfClientset, appNS, appName, interlaceNS)
	if err != nil {
		return errors.Wrap(err, "failed to get InterlaceProfile which matches with the application")
	}
	if profile == nil {
		log.Info("no profiles matched with the detected Application sync. skip this time.")
		return nil
	}

	sourceVerified := false

	log.Infof("[%s]: Interlace detected update of existing Application resource: %s", appName, appName)
	var valueFiles []string
	var releaseName string
	var values string
	var version string
	isHelm := newApp.Spec.Source.IsHelm()
	if isHelm {
		//ValuesFiles is a list of Helm value files to use when generating a template
		valueFiles = newApp.Spec.Source.Helm.ValueFiles
		releaseName = newApp.Spec.Source.Helm.ReleaseName
		values = newApp.Spec.Source.Helm.Values
		version = newApp.Spec.Source.Helm.Version
		log.Info("len(valueFiles)", len(valueFiles))
		log.Info("releaseName", releaseName)
		log.Info("version", version)
		appPath = filepath.Join(interlaceConfig.WorkspaceDir, appName)
	}

	appDirPath := filepath.Join(interlaceConfig.WorkspaceDir, appName, appPath)
	chart := newApp.Spec.Source.Chart
	appData, _ := application.NewApplicationData(appName, appNS, appPath, appDirPath, appClusterUrl,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha,
		appDestNamespace, chart, isHelm, valueFiles, releaseName, values, version)

	log.Infof("[%s]: Interlace detected update of an exsiting Application resource: %s", appName, appName)

	sourceVerifySkipped := false
	sourceVerified, err = verifySourceMaterial(*appData, profile, isHelm, kubeConfig, interlaceNS)
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
	if len(prof.Spec.Protection.Generators) > 0 {
		for i, appConfig := range prof.Spec.Applications {
			keyConfig := appConfig.SignConfig.KeyConfig
			if keyConfig.PEM == "" && keyConfig.Secret == "" {
				continue
			}
			privkeyBytes, err := getKeyPEMFromKeyConfig(keyConfig, kubeConfig, interlaceNS)
			if err != nil {
				return errors.Wrap(err, "failed to get private key from profile")
			}
			pubkeyBytes, err := extractPubkeyFromPrivKey(privkeyBytes)
			if err != nil {
				return errors.Wrap(err, "failed to get public key from private key")
			}
			err = generateEnforceRuleForProfile(prof, i, pubkeyBytes, kubeConfig, interlaceNS)
			if err != nil {
				return errors.Wrap(err, "failed to generate enforce rule")
			}
			log.Infof("enforce rule is generated for profile \"%s\"", prof.GetName())
		}

		dynamicClient, err := dynamic.NewForConfig(kubeConfig)
		if err != nil {
			return errors.Wrap(err, "failed to create a dynamic client")
		}
		err = generateApplicationSetForProfile(prof, dynamicClient, argocdNS)
		if err != nil {
			return errors.Wrap(err, "failed to generate application")
		}
		log.Infof("application is generated for profile \"%s\"", prof.GetName())
	}

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

func getMatchedProfile(iProfClientset iprofClientset.Interface, namespace, name, interlaceNS string) (*iprof.InterlaceProfile, error) {
	iprofList, err := iProfClientset.InterlaceV1beta1().InterlaceProfiles(interlaceNS).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var matched *iprof.InterlaceProfile
	for i, p := range iprofList.Items {
		if !p.Match(name) {
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
		var pubkeyBytes []byte
		var err error
		var keyConfig iprof.KeyConfig
		for _, appConfig := range profile.Spec.Applications {
			if appConfig.Match(appData.AppName) {
				keyConfig = appConfig.VerifyConfig.KeyConfig
				break
			}
		}
		if keyConfig.PEM == "" && keyConfig.Secret == "" {
			return false, nil
		}
		pubkeyBytes, err = getKeyPEMFromKeyConfig(keyConfig, kubeConfig, interlaceNS)
		if err != nil {
			log.Errorf("Error in getting key: %s", err.Error())
			return false, err
		}
		return verify.VerifyKustomizeSourceMaterial(appPath, appSourceRepoUrl, pubkeyBytes)
	}
}

func signManifestAndGenerateProvenance(appData application.ApplicationData, profile *iprof.InterlaceProfile, created bool, appProvClientset appprovClientset.Interface, sourceVerified, sourceVerifySkipped bool, kubeConfig *rest.Config, interlaceNS string) (storage.StorageBackend, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return nil, nil
	}

	storageConfig := storage.StorageConfig{
		ManifestStorageType:  interlaceConfig.ManifestStorageType,
		AppData:              appData,
		Profile:              profile,
		AppProvClientset:     appProvClientset,
		InterlaceNS:          interlaceConfig.ArgocdInterlaceNamespace,
		MaxResultsInResource: interlaceConfig.MaxResultsInResource,
		UploadTLog:           interlaceConfig.UploadTLog,
	}
	allStorageBackEnds, err := storage.InitializeStorageBackends(storageConfig, kubeConfig)
	if err != nil {
		log.Errorf("Error in initializing storage backends: %s", err.Error())
		return nil, err
	}
	storageBackend := allStorageBackEnds[interlaceConfig.ManifestStorageType]

	var provMgr provenance.ProvenanceManager
	if storageBackend != nil {

		manifestGenerated := false

		buildStartedOn := time.Now()

		log.Info("buildStartedOn:", buildStartedOn)

		if created {

			log.Infof("[%s] Interlace downloads desired manifest from ArgoCD REST API", appData.AppName)
			manifestGenerated, err = manifest.GenerateInitialManifest(appData)
			if err != nil {
				log.Errorf("Error in generating initial manifest: %s", err.Error())
				return nil, err
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
				log.Errorf("Error in generating latest manifest: %s", err.Error())
				return nil, err
			}
		}
		var privkeyBytes []byte
		var signKeyConfig iprof.KeyConfig
		for _, appConfig := range profile.Spec.Applications {
			if appConfig.Match(appData.AppName) {
				signKeyConfig = appConfig.SignConfig.KeyConfig
				break
			}
		}
		if signKeyConfig.PEM != "" || signKeyConfig.Secret != "" {
			privkeyBytes, err = getKeyPEMFromKeyConfig(signKeyConfig, kubeConfig, interlaceNS)
			if err != nil {
				log.Errorf("Error in getting key: %s", err.Error())
				return nil, err
			}
		}
		log.Info("manifestGenerated ", manifestGenerated)
		if manifestGenerated {
			err = storageBackend.StoreManifestBundle(sourceVerified, privkeyBytes)
			if err != nil {
				log.Errorf("Error in storing latest manifest bundle(signature, prov) %s", err.Error())
				return nil, err
			}
		}

		buildFinishedOn := time.Now()
		log.Info("buildFinishedOn:", buildFinishedOn)
		if manifestGenerated || interlaceConfig.AlwaysGenerateProv {
			err = storageBackend.StoreManifestProvenance(buildStartedOn, buildFinishedOn, sourceVerified, privkeyBytes)
			if err != nil {
				log.Errorf("Error in storing manifest provenance: %s", err.Error())
				return nil, err
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
	user, _ := secret.Data["user"]
	token, _ := secret.Data["token"]
	email, _ := secret.Data["email"]
	return string(user), string(token), string(email), nil
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

func generateEnforceRuleForProfile(prof *iprof.InterlaceProfile, appIndex int, pubkeyBytes []byte, kubeConfig *rest.Config, interlaceNS string) error {
	if len(prof.Spec.Protection.Generators) == 0 {
		return nil
	}
	ruleType := string(prof.Spec.Protection.PolicyType)
	ruleName := fmt.Sprintf("enforce-rule-%s-%v", prof.GetName(), appIndex)
	sourceConfig := prof.Spec.Protection.PolicySource
	patterns := []iprof.ResourceMatchPattern{}
	for _, appConfig := range prof.Spec.Applications {
		patterns = append(patterns, appConfig.SignConfig.Match...)
	}
	sigResName := repository.DefaultSignatureResourceName
	gitUser, gitToken, gitEmail, err := getGitAuthInfoFromSecret(kubeConfig, prof.Spec.Protection.PolicySource.AuthSecret, interlaceNS)
	if err != nil {
		return errors.Wrap(err, "failed to get git auth secret")
	}
	err = enforce.GenerateRule(ruleType, ruleName, sigResName, patterns, pubkeyBytes, sourceConfig, gitUser, gitToken, gitEmail)
	if err != nil {
		return errors.Wrap(err, "failed to generate enforce rule")
	}
	return nil
}

func generateApplicationSetForProfile(prof *iprof.InterlaceProfile, dynamicClient dynamic.Interface, argocdNS string) error {
	if len(prof.Spec.Protection.Generators) == 0 {
		return nil
	}
	appsetGenerators, err := ParseGenerators(prof.Spec.Protection.Generators)
	if err != nil {
		return errors.Wrap(err, "failed to parse generators in interlace profile")
	}
	sourceConfig := prof.Spec.Protection.PolicySource
	destConfig := prof.Spec.Protection.Destination
	appsetName := fmt.Sprintf("application-set-%s", prof.GetName())
	repoPath := sourceConfig.Path
	if repoPath == "" {
		repoPath = "./"
	}
	appset := &appsetv1.ApplicationSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: appsetv1.GroupVersion.String(),
			Kind:       "ApplicationSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: appsetName,
		},
		Spec: appsetv1.ApplicationSetSpec{
			// currently we support only "elements" list for generator
			Generators: appsetGenerators,
			// template
			Template: appsetv1.ApplicationSetTemplate{
				ApplicationSetTemplateMeta: appsetv1.ApplicationSetTemplateMeta{
					Name: fmt.Sprintf("application-%s-{{cluster}}", prof.GetName()),
				},
				Spec: appv1.ApplicationSpec{
					Source: appv1.ApplicationSource{
						RepoURL:        sourceConfig.URL,
						Path:           repoPath,
						TargetRevision: sourceConfig.Branch,
					},
					Destination: appv1.ApplicationDestination{
						Server:    destConfig.Server,
						Namespace: destConfig.Namespace,
					},
					SyncPolicy: &appv1.SyncPolicy{
						Automated: &appv1.SyncPolicyAutomated{},
					},
				},
			},
			SyncPolicy: &appsetv1.ApplicationSetSyncPolicy{},
		},
	}
	exists := false
	appSetGVR := appsetv1.GroupVersion.WithResource("applicationsets")
	current, err := dynamicClient.Resource(appSetGVR).Namespace(argocdNS).Get(context.Background(), appsetName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			exists = false
		} else {
			return errors.Wrap(err, "failed to get the current application set")
		}
	} else {
		currentBytes, _ := json.Marshal(current.Object)
		var currentAppset appsetv1.ApplicationSet
		_ = json.Unmarshal(currentBytes, &currentAppset)
		appset.ObjectMeta = currentAppset.ObjectMeta
		exists = true
	}
	appsetBytes, _ := json.Marshal(appset)
	var unstAppset *unstructured.Unstructured
	_ = json.Unmarshal(appsetBytes, &unstAppset)
	if exists {
		_, err := dynamicClient.Resource(appSetGVR).Namespace(argocdNS).Update(context.Background(), unstAppset, metav1.UpdateOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to update an application set")
		}
	} else {
		_, err := dynamicClient.Resource(appSetGVR).Namespace(argocdNS).Create(context.Background(), unstAppset, metav1.CreateOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to create an application set")
		}
	}
	return nil
}

func ParseGenerators(generators []iprof.Generator) ([]appsetv1.ApplicationSetGenerator, error) {
	gs := []appsetv1.ApplicationSetGenerator{}
	for _, generator := range generators {
		var g appsetv1.ApplicationSetGenerator
		gBytes, err := json.Marshal(generator)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal Generator")
		}
		err = json.Unmarshal(gBytes, &g)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Generator bytes to ApplicationSetGenerator")
		}
		gs = append(gs, g)
	}
	return gs, nil
}
