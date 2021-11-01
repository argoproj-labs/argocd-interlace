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
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var cfg *rest.Config

func GetInClusterConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return config, nil
}

func IsInCluster() bool {
	_, err := rest.InClusterConfig()
	if err == nil {
		return true
	} else {
		return false
	}
}

func GetKubeConfig() (*rest.Config, error) {
	if cfg != nil {
		return cfg, nil
	}
	config, err := GetInClusterConfig()

	if err != nil || config == nil {
		return nil, err
	}
	return config, nil
}

func ApplyPatch(name, namespace string, policyObj unstructured.Unstructured, annotations map[string]string) error {

	config, err := GetKubeConfig()
	gvr := schema.GroupVersionResource{
		Group:    "policy.open-cluster-management.io",
		Version:  "v1",
		Resource: "policies",
	}

	if err != nil {
		return fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}

	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	resource, err := dyClient.Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})

	oldannotations := resource.GetAnnotations()

	newannotations := policyObj.GetAnnotations()

	oldannotations["cosign.sigstore.dev/message"] = newannotations["cosign.sigstore.dev/message"]
	oldannotations["cosign.sigstore.dev/signature"] = newannotations["cosign.sigstore.dev/signature"]

	resource.SetAnnotations(oldannotations)

	updateObj, err := dyClient.Resource(gvr).Namespace(namespace).Update(context.Background(), resource, metav1.UpdateOptions{})

	if err != nil {
		log.Info("Policy udpate error !", err.Error())
		log.Info(updateObj)
		return err
	}

	return nil
}
