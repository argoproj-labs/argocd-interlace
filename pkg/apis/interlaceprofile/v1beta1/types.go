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

package v1beta1

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Applications []ApplicationConfig `json:"applications,omitempty"`
	Protection   ProtectionConfig    `json:"protection,omitempty"`
}

type ApplicationConfig struct {
	Selector         ApplictionSelector  `json:"selector,omitempty"`
	Actions          []ApplicationAction `json:"actions,omitempty"`
	VerifyConfig     VerifyConfig        `json:"verifyConfig,omitempty"`
	SignConfig       SignConfig          `json:"signConfig,omitempty"`
	ProvenanceConfig ProvenanceConfig    `json:"provenanceConfig,omitempty"`
}

type ApplictionSelector struct {
	Name string `json:"name,omitempty"`
}

type VerifyConfig struct {
	KeyConfig KeyConfig `json:"key,omitempty"`
}

type SignConfig struct {
	KeyConfig   KeyConfig              `json:"key,omitempty"`
	Match       []ResourceMatchPattern `json:"match,omitempty"`
	StorageType StorageType            `json:"storageType,omitempty"`
}

type ProvenanceConfig struct {
	KeyConfig KeyConfig `json:"key,omitempty"`
}

type ResourceMatchPattern struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

type KeyConfig struct {
	Secret string `json:"secret,omitempty"`
	PEM    string `json:"PEM,omitempty"`
}

type Generator interface {
	DeepCopyGenerator() Generator
}

type Destination struct {
	Server    string `json:"server,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type ProtectionConfig struct {
	Generators   []Generator                  `json:"generators,omitempty"`
	Destination  Destination                  `json:"destination,omitempty"`
	PolicyType   ProtectionPolicyType         `json:"policyType,omitempty"`
	PolicySource ProtectionPolicySourceConfig `json:"policySource,omitempty"`
}

type ProtectionPolicySourceConfig struct {
	Type       ProtectionPolicySourceType `json:"type,omitempty"`
	URL        string                     `json:"url,omitempty"`
	Branch     string                     `json:"branch,omitempty"`
	Path       string                     `json:"path,omitempty"`
	AuthSecret string                     `json:"authSecret,omitempty"`
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

func (p *InterlaceProfile) Match(name string) bool {
	for _, appCfg := range p.Spec.Applications {
		if appCfg.Match(name) {
			return true
		}
	}
	return false
}

func (c ApplicationConfig) Match(name string) bool {
	return match(c.Selector.Name, name)
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
