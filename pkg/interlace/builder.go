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
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/manifest"
	"github.com/IBM/argocd-interlace/pkg/provenance"
	"github.com/IBM/argocd-interlace/pkg/storage"
	"github.com/IBM/argocd-interlace/pkg/storage/annotation"
	"github.com/IBM/argocd-interlace/pkg/storage/git"
	"github.com/IBM/argocd-interlace/pkg/utils"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	corev1 "k8s.io/api/core/v1"
)

func CreateEventHandler(app *appv1.Application) error {

	appName := app.ObjectMeta.Name
	appClusterUrl := app.Spec.Destination.Server

	// Do not use app.Status  in create event.
	appSourceRepoUrl := app.Spec.Source.RepoURL
	appSourceRevision := app.Spec.Source.TargetRevision
	appSourceCommitSha := ""
	// Create does not have app.Status.Sync.Revision information, we need to extract commitsha by API
	commitSha := provenance.GitLatestCommitSha(app.Spec.Source.RepoURL, app.Spec.Source.TargetRevision)
	if commitSha != "" {
		appSourceCommitSha = commitSha
	}

	log.Infof("[INFO][%s]: Interlace detected creation of new Application resource: %s", appName, appName)

	appPath := app.Spec.Source.Path
	appSourcePreiviousCommitSha := ""

	sourceVerified, err := verifySourceMaterial(appPath, appSourceRepoUrl)

	if err != nil {
		return err
	}

	if sourceVerified {
		log.Infof("[INFO][%s]: Interlace's signature verification of Application source materials succeeded: %s", appName, appName)

		err := signManifestAndGenerateProvenance(appName, appPath, appClusterUrl,
			appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, true,
		)
		if err != nil {
			return err
		}
	} else {
		log.Infof("[INFO][%s]: Interlace's signature verification of Application source materials failed: %s", appName, appName)
		return err
	}
	return nil
}

// Handles update events for the Application CRD
// Triggers the following steps:
// Retrive latest manifest via ArgoCD api
// Sign manifest
// Generate provenance record
// Store signed manifest, provenance record in OCI registry/Git
func UpdateEventHandler(oldApp, newApp *appv1.Application) error {

	generateManifest := false
	created := false

	if oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "Synced" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		// This branch handle the case in which app is being updated,
		// the updates contains the necessary information (commit hash etc.)
		generateManifest = true
	}

	if generateManifest {

		appName := newApp.ObjectMeta.Name
		appPath := newApp.Status.Sync.ComparedTo.Source.Path
		appSourceRepoUrl := newApp.Status.Sync.ComparedTo.Source.RepoURL
		appSourceRevision := newApp.Status.Sync.ComparedTo.Source.TargetRevision
		appSourceCommitSha := newApp.Status.Sync.Revision
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

		log.Infof("[INFO][%s]: Interlace detected update of existing Application resource: %s", appName, appName)

		sourceVerified, err := verifySourceMaterial(appPath, appSourceRepoUrl)

		if err != nil {
			return err
		}

		if sourceVerified {
			log.Infof("[INFO][%s]: Interlace's signature verification of Application source materials succeeded: %s", appName, appName)

			err := signManifestAndGenerateProvenance(appName, appPath, appClusterUrl,
				appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, created)
			if err != nil {
				return err
			}
		} else {
			log.Infof("[INFO][%s]: Interlace's signature verification of Application source materials failed: %s", appName, appName)
			return err
		}

	}
	return nil
}

func verifySourceMaterial(appPath, appSourceRepoUrl string) (bool, error) {

	interlaceConfig, err := config.GetInterlaceConfig()

	host, orgRepo, path, gitRef, gitSuff := provenance.ParseGitUrl(appSourceRepoUrl)

	log.Info("appSourceRepoUrl ", appSourceRepoUrl)
	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff

	log.Info("url:", url)

	r, err := provenance.GetTopGitRepo(url)
	if err != nil {
		log.Errorf("Error git clone:  %s", err.Error()) // ##CHANGEDX
		return false, err
	}

	baseDir := filepath.Join(r.RootDir, appPath)

	log.Info(" baseDir: ", baseDir)

	keyPath := "/etc/keyring-secret/pubring.gpg"

	srcMatPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialHashList)
	srcMatSigPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialSignature)

	verification_target, err := os.Open(srcMatPath)
	signature, err := os.Open(srcMatSigPath)
	flag, message, _, _, _ := verifySignature(keyPath, verification_target, signature)

	log.Info("flag:", flag)
	log.Info("message:", message)

	hashCompareSuccess := false
	if flag {
		hashCompareSuccess, err = compareHash(srcMatPath, baseDir)
		log.Info("hashCompareSuccess:", hashCompareSuccess)
		if err != nil {
			return hashCompareSuccess, err
		}
		return hashCompareSuccess, nil
	}

	return flag, nil
}

func verifySignature(keyPath string, msg, sig *os.File) (bool, string, *Signer, []byte, error) {

	if keyRing, err := LoadKeyRing(keyPath); err != nil {
		return false, "Error when loading key ring", nil, nil, err
	} else if signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msg, sig); signer == nil {
		log.Info("msg:", msg)
		log.Info("sig:", sig)
		if err != nil {
			log.Error("Signature verification error:", err.Error())
		}
		return false, "Signed by unauthrized subject (signer is not in public key), or invalid format signature", nil, nil, nil
	} else {
		idt := GetFirstIdentity(signer)
		fingerprint := ""
		if signer.PrimaryKey != nil {
			fingerprint = fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
		}
		return true, "", NewSignerFromUserId(idt.UserId), []byte(fingerprint), nil
	}
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}

type Signer struct {
	Email              string `json:"email,omitempty"`
	Name               string `json:"name,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	Fingerprint        []byte `json:"finerprint"`
}

func NewSignerFromUserId(uid *packet.UserId) *Signer {
	return &Signer{
		Email:   uid.Email,
		Name:    uid.Name,
		Comment: uid.Comment,
	}
}

func LoadKeyRingSecret(keyPath string) error {

	secretName := "keyring-secret"

	obj, err := kubeutil.GetResource("v1", "Secret", "argocd-interlace", secretName)

	if err != nil {
		log.Warn(fmt.Sprintf("Failed to get secret `%s`; %s", secretName, err.Error()))

	}
	objBytes, _ := json.Marshal(obj)
	var res corev1.Secret
	_ = json.Unmarshal(objBytes, &res)

	newPathFile := "pubring.gpg"
	pubKeyBytes, ok := res.Data[newPathFile]
	if !ok {
		log.Warn(fmt.Sprintf("Failed to get a pubKeyBytes from secret `%s`, file %s", secretName, newPathFile))
	}

	err = ioutil.WriteFile(keyPath, pubKeyBytes, 0755)
	return nil
}
func LoadKeyRing(keyPath string) (openpgp.EntityList, error) {
	entities := []*openpgp.Entity{}
	var retErr error
	kpath := filepath.Clean(keyPath)
	if keyRingReader, err := os.Open(kpath); err != nil {
		log.Warn("Failed to open keyring")
		retErr = err
	} else {
		tmpList, err := openpgp.ReadKeyRing(keyRingReader)
		if err != nil {
			log.Warn("Failed to read keyring")
			retErr = err
		}
		for _, tmp := range tmpList {
			for _, id := range tmp.Identities {
				log.Info("identity name ", id.Name, " id.UserId.Name: ", id.UserId.Name, " id.UserId.Email:", id.UserId.Email)
			}
			entities = append(entities, tmp)
		}
	}
	return openpgp.EntityList(entities), retErr
}

func compareHash(sourceMaterialPath string, baseDir string) (bool, error) {
	sourceMaterial, err := ioutil.ReadFile(sourceMaterialPath)

	if err != nil {
		log.Errorf("Error in reading sourceMaterialPath:  %s", err.Error())
		return false, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(sourceMaterial)))

	for scanner.Scan() {
		l := scanner.Text()
		log.Info("scaned text ", l)
		data := strings.Split(l, " ")
		fmt.Println(" data ", data, " len(data): ", len(data))
		if len(data) > 2 {
			hash := data[0]
			path := data[2]

			absPath := filepath.Join(baseDir, "/", path)
			computedFileHash, err := computeHash(absPath)
			log.Info("file: ", path, " hash:", hash, " absPath:", absPath, " computedFileHash: ", computedFileHash)
			if err != nil {
				return false, err
			}

			if hash != computedFileHash {
				return false, nil
			}
		} else {
			continue
		}
	}
	return true, nil
}

func computeHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Info("Error in opening file !")
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Info("Error in copying file !")
		return "", err
	}

	sum := h.Sum(nil)
	hashstring := fmt.Sprintf("%x", sum)
	return hashstring, nil
}

func signManifestAndGenerateProvenance(appName, appPath, appClusterUrl,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string, created bool) error {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
		return nil
	}

	manifestStorageType := interlaceConfig.ManifestStorageType

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	if appSourceRepoUrl == interlaceConfig.ManifestGitUrl {
		log.Info("Skipping changes in application that manages manifest signatures")
		return nil
	}

	//tokens := strings.Split(strings.TrimSuffix(appClusterUrl, "https://"), "https://")
	tokens := strings.Split(strings.TrimSuffix(appClusterUrl, "."), ".")
	clusterName := tokens[1]

	allStorageBackEnds, err := storage.InitializeStorageBackends(appName, appPath, appDirPath, appClusterUrl,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha, manifestStorageType, clusterName,
	)

	if err != nil {
		log.Errorf("Error in initializing storage backends: %s", err.Error())
		return err
	}

	storageBackend := allStorageBackEnds[manifestStorageType]
	log.Info("manifestStorageType ", manifestStorageType)
	log.Info("storageBackend ", storageBackend)
	if storageBackend != nil {

		manifestGenerated := false

		loc, _ := time.LoadLocation("UTC")
		buildStartedOn := time.Now().In(loc)
		err = storageBackend.SetBuildStartedOn(buildStartedOn)
		if err != nil {
			log.Errorf("Error in setting  build start time: %s", err.Error())
			return err
		}

		if created {
			log.Info("created scenario")
			log.Infof("[INFO][%s] Interlace downloads desired manifest from ArgoCD REST API", appName)
			manifestGenerated, err = manifest.GenerateInitialManifest(appName, appPath, appDirPath)
			if err != nil {
				log.Errorf("Error in generating initial manifest: %s", err.Error())
				return err
			}
		} else {
			log.Info("update scenario")
			log.Infof("[INFO][%s] Interlace downloads desired manifest from ArgoCD REST API", appName)
			yamlBytes, err := storageBackend.GetLatestManifestContent()
			if err != nil {
				log.Errorf("Error in retriving latest manifest content: %s", err.Error())

				if storageBackend.Type() == git.StorageBackendGit || storageBackend.Type() == annotation.StorageBackendAnnotation {
					log.Info("Going to try generating initial manifest again")
					manifestGenerated, err = manifest.GenerateInitialManifest(appName, appPath, appDirPath)
					log.Info("manifestGenerated after generating initial manifest again: ", manifestGenerated)
					if err != nil {
						log.Errorf("Error in generating initial manifest: %s", err.Error())
						return err
					}
				} else {
					return err
				}

			}
			log.Infof("[INFO]: Argocd Interlace generates manifest %s", appName)
			manifestGenerated, err = manifest.GenerateManifest(appName, appDirPath, yamlBytes)
			if err != nil {
				log.Errorf("Error in generating latest manifest: %s", err.Error())
				return err
			}
		}
		log.Info("manifestGenerated ", manifestGenerated)
		if manifestGenerated {

			err = storageBackend.StoreManifestBundle()
			if err != nil {
				log.Errorf("Error in storing latest manifest bundle(signature, prov) %s", err.Error())
				return err
			}

			mode := interlaceConfig.ManifestAppSetMode
			if storageBackend.Type() == git.StorageBackendGit && mode != "appset" {
				log.Info("check application name application: ", appName)
				response, err := listApplication(appName)

				if err != nil {
					log.Errorf("Error in retriving list of applications %s", err.Error())
					return err
				}

				log.Info("response from listing application: ", response)

				errorMsg := gjson.Get(response, "error")
				if strings.Contains(errorMsg.String(), "not found") {

					log.Info("Going create new application for manifest")

					sourcePath := filepath.Join(utils.MANIFEST_DIR, clusterName)

					response, err = createApplication(appName, appPath, appClusterUrl, sourcePath)

					if err != nil {
						log.Errorf("Error in creating application %s", err.Error())
						return err
					}

					log.Info("create application response ", response)

				} else {
					_, err = updateApplication(appName, appPath, appClusterUrl)
					if err != nil {
						log.Errorf("Error in updating application %s", err.Error())
						return err
					}
				}
			}

		}

		buildFinishedOn := time.Now().In(loc)
		err = storageBackend.SetBuildFinishedOn(buildFinishedOn)
		if err != nil {
			log.Errorf("Error in setting  build start time: %s", err.Error())
			return err
		}

		if interlaceConfig.AlwaysGenerateProv {
			err = storageBackend.StoreManifestProvenance()
			if err != nil {
				log.Errorf("Error in storing manifest provenance: %s", err.Error())
				return err
			}
		} else {
			if manifestGenerated {
				err = storageBackend.StoreManifestProvenance()
				if err != nil {
					log.Errorf("Error in storing manifest provenance: %s", err.Error())
					return err
				}
			}
		}
	} else {

		return fmt.Errorf("Could not find storage backend")
	}

	return nil
}

func GenerateProvenance(appName, appPath, appClusterUrl,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, appSourcePreiviousCommitSha string, created bool) error {
	return nil
}
