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

	policiesv1 "github.com/open-cluster-management/governance-policy-propagator/api/v1"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

/*
	policiesv1 "github.com/open-cluster-management/governance-policy-propagator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/dynamic"
*/

var cfg *rest.Config

func getClient() (client.Client, error) {
	cfg, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}

	scm := runtime.NewScheme()
	err = scheme.AddToScheme(scm)
	policiesv1.AddToScheme(scm)
	if err != nil {
		return nil, err
	}
	cli, err := client.New(cfg, client.Options{Scheme: scm})
	if err != nil {
		return nil, err
	}
	return cli, nil
}

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

func ApplyPatch(policyObj unstructured.Unstructured, annotations map[string]string) error {
	/*
		config, err := GetKubeConfig()
		if err != nil {
			return fmt.Errorf("Error in getting k8s config; %s", err.Error())
		}
	*/

	//client, err := client.NewForConfig(config)
	/*dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}*/

	//var c client.Client

	/*
		patch := []byte(`{"metadata":{"annotations":{"version": "v2"}}}`)

		_ = c.Patch(context.Background(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "namespace",
				Name:      "name",
			},
		}, client.RawPatch(types.StrategicMergePatchType, patch))
	*/
	/*
			clientset, err := kubernetes.NewForConfig(config)
		    if err != nil {
		        panic(err.Error())
		    }

			_ = c.Patch(context.Background(), &policiesv1.Policy {
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ma4kmc3",
					Name:      "policy-generator-blog.policy-generator-blog-app",
				},
			}, client.RawPatch(types.StrategicMergePatchType, patch))
	*/

	//policiesv1.Patch
	ctx := context.Background()
	cli, err := getClient()

	err = patchApply(ctx, cli, policyObj, annotations)
	if err != nil {
		fmt.Println(err)
		log.Info("Error in patcing annotation")
	}

	return nil
}

func patchApply(ctx context.Context, cli client.Client, policyObj unstructured.Unstructured, annotations map[string]string) error {
	config, err := GetKubeConfig()
	gvr := schema.GroupVersionResource{
		Group:    "policy.open-cluster-management.io",
		Version:  "v1",
		Resource: "policies", // not "Deployment"
	}

	if err != nil {
		return fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}

	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	//var resource *unstructured.Unstructured

	//kind := "Policy"

	namespace := "policy-generator-blog"
	name := "policy-generator-blog-app" //"policy-generator-blog.policy-generator-blog-app"

	resource, err := dyClient.Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})

	oldannotations := resource.GetAnnotations()

	newannotations := policyObj.GetAnnotations()

	oldannotations["cosign.sigstore.dev/message"] = newannotations["cosign.sigstore.dev/message"]
	oldannotations["cosign.sigstore.dev/signature"] = newannotations["cosign.sigstore.dev/signature"]

	resource.SetAnnotations(oldannotations)

	log.Info("----->>>", policyObj)
	log.Info("----->>>", policyObj.GetKind(), " ", policyObj.GetName(), " ", policyObj.GetNamespace())

	log.Info("----->>>", resource)
	log.Info("----->>>", resource.GetKind(), " ", resource.GetName(), " ", resource.GetNamespace(), " ", resource.GetAnnotations())

	//obj.SetAnnotations(annotations)

	updateObj, err := dyClient.Resource(gvr).Namespace(namespace).Update(context.Background(), resource, metav1.UpdateOptions{})

	if err != nil {
		log.Info("Policy udpate error !", err.Error())
		log.Info(updateObj)
		return err
	}

	return nil
}

func patchApplyOL(ctx context.Context, cli client.Client, policyObj []byte, annotations map[string]string) error {
	var acmpolicy policiesv1.Policy

	err := cli.Get(ctx, client.ObjectKey{Namespace: "ma4kmc3", Name: "policy-generator-blog.policy-generator-blog-app"}, &acmpolicy)
	if err != nil {
		log.Info("Policy not found !")
		return err
	}

	log.Info("acmpolicy ", acmpolicy)

	acmpolicy.SetAnnotations(annotations)

	// approach 7
	/*
		payload := []patchUInt32Value{{
			Op:    "replace",
			Path:  "/spec/replicas",
			Value: scale,
		}}
		payloadBytes, _ := json.Marshal(payload)
	*/
	//appraoch 5
	//err = cli.Update(context.TODO(), &acmpolicy)

	/*if err != nil {
		log.Info("Policy can not be update !")
		return err
	}*/

	//patch := []byte(`{"metadata":{"annotations":{"version": "v2"}}}`)

	//Approach 3
	//the body of the request was in an unknown format
	//- accepted media types include: application/json-patch+json, application/merge-patch+json, application/apply-patch+yaml

	/*
		p := patch{
			Metadata: metadata{
				Annotations: annotations,
			},
		}
		patchdata, _ := json.Marshal(p)

		err = cli.Patch(context.Background(), &policiesv1.Policy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ma4kmc3",
				Name:      "policy-generator-blog.policy-generator-blog-app",
			},
		}, client.RawPatch(types.StrategicMergePatchType, patchdata))

		if err != nil {
			log.Info("Policy patch can not be done !", err.Error())
			return err
		}

	*/

	// apprach 1
	/*
		newDep := acmpolicy.DeepCopy()
		//newDep.ObjectMeta

		patch := client.MergeFrom(&acmpolicy)

		err = cli.Patch(ctx, newDep, patch)

		return err
	*/

	//approach 2  // Object 'Kind' is missing in 'unstructured object has no kind'

	/*
		patch := &unstructured.Unstructured{}

		var obj *unstructured.Unstructured
		err := yaml.Unmarshal(policyObj, &obj)
		policyObj

		patch.SetAnnotations(annotations)

		err = cli.Patch(ctx, patch, client.Apply, &client.PatchOptions{
			FieldManager: "client-sample",
			Force:        pointer.Bool(true),
		})
	*/
	/*
		var obj *unstructured.Unstructured{}
		err = yaml.Unmarshal(policyObj, &obj)
		if err != nil {
			log.Info("Policy unmarshal error !")
			return err
		}

		&obj.SetAnnotations(annotations)

		err = cli.Patch(ctx, &obj, client.Apply, &client.PatchOptions{
			FieldManager: "client-sample",
			Force:        pointer.Bool(true),
		})
	*/

	// approach 6
	/*
		pa := patch{
			Metadata: metadata{
				Annotations: annotations,
			},
		}
		patchJson, _ := json.Marshal(pa)

		err := cli.Patch(api.MergePatchType).RequestURI(n.SelfLink).Body(patchJson).Do().Error()

		err = cli.Patch(context.Background(), &policiesv1.Policy{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ma4kmc3",
				Name:      "policy-generator-blog.policy-generator-blog-app",
			},
		}, client.RawPatch(types.StrategicMergePatchType, patchdata))

		if err != nil {
			log.Info("Policy patch can not be done !", err.Error())
			return err
		}
	*/

	return nil
}

// These are used to get proper json formatting
type patch struct {
	Metadata metadata `json:"metadata,omitempty"`
}
type metadata struct {
	Annotations map[string]string `json:"annotations,omitempty"`
}
