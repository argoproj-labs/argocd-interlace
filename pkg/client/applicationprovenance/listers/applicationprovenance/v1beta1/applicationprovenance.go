/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/argoproj-labs/argocd-interlace/pkg/apis/applicationprovenance/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ApplicationProvenanceLister helps list ApplicationProvenances.
// All objects returned here must be treated as read-only.
type ApplicationProvenanceLister interface {
	// List lists all ApplicationProvenances in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.ApplicationProvenance, err error)
	// ApplicationProvenances returns an object that can list and get ApplicationProvenances.
	ApplicationProvenances(namespace string) ApplicationProvenanceNamespaceLister
	ApplicationProvenanceListerExpansion
}

// applicationProvenanceLister implements the ApplicationProvenanceLister interface.
type applicationProvenanceLister struct {
	indexer cache.Indexer
}

// NewApplicationProvenanceLister returns a new ApplicationProvenanceLister.
func NewApplicationProvenanceLister(indexer cache.Indexer) ApplicationProvenanceLister {
	return &applicationProvenanceLister{indexer: indexer}
}

// List lists all ApplicationProvenances in the indexer.
func (s *applicationProvenanceLister) List(selector labels.Selector) (ret []*v1beta1.ApplicationProvenance, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.ApplicationProvenance))
	})
	return ret, err
}

// ApplicationProvenances returns an object that can list and get ApplicationProvenances.
func (s *applicationProvenanceLister) ApplicationProvenances(namespace string) ApplicationProvenanceNamespaceLister {
	return applicationProvenanceNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ApplicationProvenanceNamespaceLister helps list and get ApplicationProvenances.
// All objects returned here must be treated as read-only.
type ApplicationProvenanceNamespaceLister interface {
	// List lists all ApplicationProvenances in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.ApplicationProvenance, err error)
	// Get retrieves the ApplicationProvenance from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.ApplicationProvenance, error)
	ApplicationProvenanceNamespaceListerExpansion
}

// applicationProvenanceNamespaceLister implements the ApplicationProvenanceNamespaceLister
// interface.
type applicationProvenanceNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ApplicationProvenances in the indexer for a given namespace.
func (s applicationProvenanceNamespaceLister) List(selector labels.Selector) (ret []*v1beta1.ApplicationProvenance, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.ApplicationProvenance))
	})
	return ret, err
}

// Get retrieves the ApplicationProvenance from the indexer for a given namespace and name.
func (s applicationProvenanceNamespaceLister) Get(name string) (*v1beta1.ApplicationProvenance, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("applicationprovenance"), name)
	}
	return obj.(*v1beta1.ApplicationProvenance), nil
}
