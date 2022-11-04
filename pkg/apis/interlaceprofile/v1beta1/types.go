//
// Copyright 2022 IBM Corporation
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

package v1beta1

import (
	"strings"

	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ApplicationAction string

const (
	VerifyAction          ApplicationAction = "verifyMaterials"
	SignAction            ApplicationAction = "signManifest"
	ProvenanceAction      ApplicationAction = "generateProvenance"
	VerifyActionShort     ApplicationAction = "verify"
	SignActionShort       ApplicationAction = "sign"
	ProvenanceActionShort ApplicationAction = "provenance"
)

type StorageType string

const (
	AnnotationStorage StorageType = "annotation"
	ResourceStorage   StorageType = "resource"
	OCIStorage        StorageType = "oci"
	ProtectionStorage StorageType = "protection"
)

type ProtectionPolicyType string

const (
	IntegrityShieldProtectionPolicyType ProtectionPolicyType = "integrity-shield"
	KyvernoProtectionPolicyType         ProtectionPolicyType = "kyverno"
)

type ProtectionPolicySourceType string

const (
	GitProtectionPolicySourceType ProtectionPolicySourceType = "git"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InterlaceProfile is a specification for a InterlaceProfile resource
type InterlaceProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   InterlaceProfileSpec   `json:"spec"`
	Status InterlaceProfileStatus `json:"status"`
}

// InterlaceProfileSpec is the spec for a InterlaceProfile resource
type InterlaceProfileSpec struct {
	ApplicationSelector []ApplicationSelector `json:"applicationSelector,omitempty"`
	VerifyConfig        VerifyConfig          `json:"verifyConfig,omitempty"`
	SignConfig          SignConfig            `json:"signConfig,omitempty"`
	ProvenanceConfig    ProvenanceConfig      `json:"provenanceConfig,omitempty"`
}

type ApplicationSelector struct {
	Name  string                `json:"name,omitempty"`
	Label *metav1.LabelSelector `json:"label,omitempty"`
}

type VerifyConfig struct {
	KeyConfig KeyConfig `json:"key,omitempty"`
}

type SignConfig struct {
	KeyConfig      KeyConfig              `json:"key,omitempty"`
	RegistryConfig RegistryConfig         `json:"registry,omitempty"`
	Match          []ResourceMatchPattern `json:"match,omitempty"`
}

type RegistryConfig struct {
	Secret           string `json:"secret,omitempty"`
	InsecureRegistry bool   `json:"insecureRegistry,omitempty"`
}

type ProvenanceConfig struct {
	KeyConfig KeyConfig `json:"key,omitempty"`
	RekorURL  string    `json:"rekorURL,omitempty"`
}

type ResourceMatchPattern struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

func (p ResourceMatchPattern) Match(obj *unstructured.Unstructured) bool {
	if p.Namespace != "" {
		if !match(p.Namespace, obj.GetNamespace()) {
			return false
		}
	}
	if p.Name != "" {
		if !match(p.Name, obj.GetName()) {
			return false
		}
	}
	apiVersion := obj.GetAPIVersion()
	gv, _ := schema.ParseGroupVersion(apiVersion)
	if p.Group != "" {
		if !match(p.Group, gv.Group) {
			return false
		}
	}
	if p.Version != "" {
		if !match(p.Version, gv.Version) {
			return false
		}
	}
	if p.Kind != "" {
		if !match(p.Kind, obj.GetKind()) {
			return false
		}
	}
	return true
}

type KeyConfig struct {
	Secret string `json:"secret,omitempty"`
	PEM    string `json:"PEM,omitempty"`
}

// InterlaceProfileStatus is the status for a InterlaceProfile resource
type InterlaceProfileStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// InterlaceProfileList is a list of InterlaceProfile resources
type InterlaceProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []InterlaceProfile `json:"items"`
}

func (p *InterlaceProfile) Match(app *appv1.Application) bool {
	if len(p.Spec.ApplicationSelector) == 0 {
		return true
	}
	for _, selector := range p.Spec.ApplicationSelector {
		if selector.Match(app) {
			return true
		}
	}
	return false
}

func (s ApplicationSelector) Match(app *appv1.Application) bool {
	if s.Name != "" {
		if !match(s.Name, app.GetName()) {
			return false
		}
	}
	if s.Label != nil {
		selector, err := metav1.LabelSelectorAsSelector(s.Label)
		if err != nil {
			return false
		}
		if !selector.Matches(labels.Set(app.GetLabels())) {
			return false
		}
	}
	// if selector is empty, matches all applications
	return true
}

func match(pattern, value string) bool {
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	} else {
		return pattern == value
	}
}
