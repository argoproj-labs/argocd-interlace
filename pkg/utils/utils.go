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
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	cligen "github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	cliopt "github.com/sigstore/cosign/cmd/cosign/cli/options"
	clisign "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	rekorServerEnvKey               = "REKOR_SERVER"
	defaultRekorServerURL           = "https://rekor.sigstore.dev"
	defaultOIDCIssuer               = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID             = "sigstore"
	cosignPasswordEnvKey            = "COSIGN_PASSWORD"
	defaultTlogUploadTimeout        = 10
	defaultKeylessTlogUploadTimeout = 90 // set to 90s for keyless as cosign recommends it in the help message
)

//GetK8sClient returns a kubernetes client and config
func GetK8sClient(configpath string) (*kubernetes.Clientset, *rest.Config, error) {

	if configpath == "" {
		log.Debug("Using Incluster configuration")

		config, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("Error occured while reading incluster kubeconfig %s", err.Error())
			return nil, nil, err
		}
		clientset, _ := kubernetes.NewForConfig(config)
		return clientset, config, nil
	}

	config, err := clientcmd.BuildConfigFromFlags("", configpath)
	if err != nil {
		log.Errorf("Error occured while reading kubeconfig %s ", err.Error())
		return nil, nil, err
	}
	clientset, _ := kubernetes.NewForConfig(config)
	return clientset, config, nil
}

func GetSecret(kubeConfig *rest.Config, namespace, name string) (*corev1.Secret, error) {

	coreV1Client, err := clientcorev1.NewForConfig(kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init core v1 client to get secret")
	}
	secret, err := coreV1Client.Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret")
	}
	return secret, nil

}

func WriteToFile(str, dirPath, filename string) error {

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			log.Errorf("Error occured while creating a dir %s ", err.Error())
			return err
		}
	}

	absFilePath := filepath.Join(dirPath, filename)

	f, err := os.Create(absFilePath)
	if err != nil {
		log.Errorf("Error occured while opening file %s ", err.Error())
		return err
	}

	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		log.Errorf("Error occured while writing to file %s ", err.Error())
		return err
	}

	return nil

}

func UploadManifestImage(manifest []byte, imageRef string, allowInsecureRegistry bool, secretKc *SecretKeyChain) error {
	dir, err := os.MkdirTemp("", "manifest-image")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fpath := filepath.Join(dir, "manifest.yaml")
	err = os.WriteFile(fpath, manifest, 0644)
	if err != nil {
		return err
	}
	files := []cremote.File{cremote.FileFromFlag(fpath)}
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}
	mediaTypeGetter := cremote.DefaultMediaTypeGetter
	remoteAuthOption := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	remoteContextOption := remote.WithContext(context.Background())
	registryOptions := options.RegistryOptions{AllowInsecure: allowInsecureRegistry}
	remoteOptions := registryOptions.GetRegistryClientOpts(context.Background())
	remoteOptions = append(remoteOptions, remoteAuthOption, remoteContextOption)
	if secretKc != nil {
		remoteOptions = append(remoteOptions, remote.WithAuthFromKeychain(secretKc))
	}
	_, err = cremote.UploadFiles(ref, files, mediaTypeGetter, remoteOptions...)
	if err != nil {
		return err
	}
	return nil
}

func SignImage(imageRef string, privKey []byte, rekorURL string, uploadTlog bool, allowInsecureRegistry bool, secretKc *SecretKeyChain) error {
	dir, err := os.MkdirTemp("", "sign-image")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	keyPath := filepath.Join(dir, "sign-image.key")
	err = os.WriteFile(keyPath, privKey, 0600)
	if err != nil {
		return err
	}

	// TODO: add support for sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	var rekorSeverURL string
	if rekorURL == "" {
		rekorSeverURL = GetRekorServerURL()
	} else {
		rekorSeverURL = rekorURL
	}
	fulcioServerURL := fulcioapi.SigstorePublicServerURL

	rootOpt := &cliopt.RootOptions{Timeout: defaultTlogUploadTimeout * time.Second}
	opt := cliopt.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}
	opt.PassFunc = cligen.GetPass
	opt.KeyRef = keyPath
	regOpt := cliopt.RegistryOptions{AllowInsecure: allowInsecureRegistry}
	if secretKc != nil {
		regOpt.Keychain = secretKc
	}

	outputSignaturePath := ""
	outputCertificatePath := ""
	noTlogUpload := !(uploadTlog)
	return clisign.SignCmd(rootOpt, opt, regOpt, nil, []string{imageRef}, "", "", true, outputSignaturePath, outputCertificatePath, "", false, false, "", noTlogUpload)
}

func GetImageHash(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", err
	}
	hash, err := img.Digest()
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func FileExist(fpath string) bool {
	if _, err := os.Stat(fpath); err == nil {
		return true
	}
	return false
}

func ComputeHash(filePath string) (string, error) {
	if FileExist(filePath) {
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
	return "", fmt.Errorf("File not found ")
}

func CmdExec(baseCmd, dir string, args ...string) (string, error) {
	cmd := exec.Command(baseCmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if dir != "" {
		cmd.Dir = dir
	}
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, stderr.String())
	}
	out := stdout.String()
	return out, nil
}

func GetCosignPassword() string {
	return os.Getenv(cosignPasswordEnvKey)
}

func GetRekorServerURL() string {
	url := os.Getenv(rekorServerEnvKey)
	if url == "" {
		url = defaultRekorServerURL
	}
	return url
}

type SecretKeyChain struct {
	Name       string
	Namespace  string
	KubeConfig *rest.Config
}

func (kc *SecretKeyChain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	secret, err := GetSecret(kc.KubeConfig, kc.Namespace, kc.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get secret for registry access")
	}
	configStr := secret.Data[".dockerconfigjson"]
	configBytes := []byte(configStr)
	cf, err := config.LoadFromReader(bytes.NewBuffer(configBytes))
	if err != nil {
		return nil, err
	}

	var cfg, empty types.AuthConfig
	for _, key := range []string{
		target.String(),
		target.RegistryStr(),
	} {
		if key == name.DefaultRegistry {
			key = authn.DefaultAuthKey
		}

		cfg, err = cf.GetAuthConfig(key)
		if err != nil {
			return nil, err
		}
		if cfg != empty {
			break
		}
	}
	if cfg == empty {
		return authn.Anonymous, nil
	}

	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}
