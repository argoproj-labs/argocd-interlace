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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ApplicationProvenance is a specification for a ApplicationProvenance resource
type ApplicationProvenance struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationProvenanceSpec   `json:"spec"`
	Status ApplicationProvenanceStatus `json:"status"`
}

// ApplicationProvenanceSpec is the spec for a ApplicationProvenance resource
type ApplicationProvenanceSpec struct {
	Application ApplicationRef `json:"application"`
}

type ApplicationRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// ApplicationProvenanceStatus is the status for a ApplicationProvenance resource
type ApplicationProvenanceStatus struct {
	LastUpdated metav1.Time `json:"lastUpdated,omitempty"`
	Provenance  []byte      `json:"provenance,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ApplicationProvenanceList is a list of ApplicationProvenance resources
type ApplicationProvenanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ApplicationProvenance `json:"items"`
}
