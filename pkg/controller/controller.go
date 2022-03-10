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

package controller

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	appprovClientset "github.com/IBM/argocd-interlace/pkg/client/clientset/versioned"
	interlaceCfg "github.com/IBM/argocd-interlace/pkg/config"
	"github.com/IBM/argocd-interlace/pkg/interlace"
	"github.com/IBM/argocd-interlace/pkg/utils"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type controller struct {
	applicationClientset     appClientset.Interface
	appProvClientset         appprovClientset.Interface
	informer                 cache.SharedIndexInformer
	appRefreshQueue          workqueue.RateLimitingInterface
	argocdNamespace          string
	argocdInterlaceNamespace string
}

func Start(ctx context.Context, kubeconfig string, argocdNamespace string, config *interlaceCfg.InterlaceConfig) {
	_, cfg, err := utils.GetClient(kubeconfig)
	appClientset := appClientset.NewForConfigOrDie(cfg)
	if err != nil {
		log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	}
	appProvClientset := appprovClientset.NewForConfigOrDie(cfg)
	if err != nil {
		log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	}

	interlaceNS := ""
	if config != nil {
		interlaceNS = config.ArgocdInterlaceNamespace
	}

	c := newController(appClientset, appProvClientset, argocdNamespace, interlaceNS)
	c.Run(ctx)
}

func (ctrl *controller) newApplicationInformer(applicationClientset appClientset.Interface) cache.SharedIndexInformer {

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (apiruntime.Object, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.argocdNamespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.argocdNamespace).Watch(context.TODO(), options)
			},
		},
		&appv1.Application{},
		0,
		cache.Indexers{},
	)
	return informer
}

func newController(applicationClientset appClientset.Interface, appProvClientset appprovClientset.Interface, argocdNamespace, interlaceNS string) *controller {
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	ctrl := &controller{
		applicationClientset:     applicationClientset,
		appProvClientset:         appProvClientset,
		appRefreshQueue:          q,
		argocdNamespace:          argocdNamespace,
		argocdInterlaceNamespace: interlaceNS,
	}

	appInformer := ctrl.newApplicationInformer(applicationClientset)
	appInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)

			app, ok := obj.(*appv1.Application)

			if ok {
				err := interlace.CreateEventHandler(app, appProvClientset, interlaceNS)
				if err != nil {
					log.Errorf("Error in handling create event: %s", err.Error())
				}
			}

			if err == nil {
				ctrl.appRefreshQueue.Add(key)
			}

		},
		UpdateFunc: func(old, new interface{}) {
			if !ctrl.canProcessApp(old) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(old)
			oldApp, oldOK := old.(*appv1.Application)
			newApp, newOK := new.(*appv1.Application)
			if oldOK && newOK {
				err := interlace.UpdateEventHandler(oldApp, newApp, appProvClientset, interlaceNS)
				if err != nil {
					log.Errorf("Error in handling update event: %s", err.Error())
				}
			}

			if err == nil {
				ctrl.appRefreshQueue.Add(key)
			}

		},
		DeleteFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)

			if err == nil {
				log.Debug("Event received of type delete for key ", key)
				//ctrl.appRefreshQueue.Add(key)
			}

		},
	})

	ctrl.informer = appInformer
	return ctrl
}

func (c *controller) canProcessApp(obj interface{}) bool {
	_, ok := obj.(*appv1.Application)
	if ok {
		return ok
	}
	return false
}

func (c *controller) Run(ctx context.Context) {

	defer utilruntime.HandleCrash()    //this will handle panic and won't crash the process
	defer c.appRefreshQueue.ShutDown() //shutdown all workqueue and terminate all workers

	log.Info("Starting argocd-interlace...")

	go c.informer.Run(ctx.Done())

	log.Info("Synchronizing events...")

	//synchronize the cache before starting to process events
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		log.Info("synchronization failed...")
		return
	}

	log.Info("Synchronization complete!")
	log.Info("Ready to process events")

	go wait.Until(func() {
		for c.processNextItem() {
			// continue looping
		}
	}, time.Second, ctx.Done())
	<-ctx.Done()
}

func (c *controller) processNextItem() (processNext bool) {
	log.Debug("Check if new events in queue ", c.appRefreshQueue.Len())

	appKey, shutdown := c.appRefreshQueue.Get()

	if shutdown {
		processNext = false
		return
	}

	processNext = true
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from panic: %+v\n%s", r, debug.Stack())
		}
		c.appRefreshQueue.Done(appKey)
	}()

	err := c.processItem(appKey.(string))
	if err == nil {
		c.appRefreshQueue.Forget(appKey)
		return true
	}
	return true
}

func (c *controller) processItem(key string) error {
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("Error fetching object with key %s from store: %v", key, err)
	}

	if !exists {
		// This happens after app was deleted, but the work queue still had an entry for it.
		return nil
	}
	_, ok := obj.(*appv1.Application)
	if !ok {
		log.Warnf("Key '%s' in index is not an application", key)
		return nil
	}

	return nil
}
