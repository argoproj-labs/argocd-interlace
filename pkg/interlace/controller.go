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

package interlace

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	interlaceprofilev1beta1 "github.com/argoproj-labs/argocd-interlace/pkg/apis/interlaceprofile/v1beta1"
	appprovClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/applicationprovenance/clientset/versioned"
	iprofClientset "github.com/argoproj-labs/argocd-interlace/pkg/client/interlaceprofile/clientset/versioned"
	interlaceCfg "github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	ApplicationKind      = "Application"
	InterlaceProfileKind = "InterlaceProfile"
)

type controller struct {
	kubeConfig               *rest.Config
	appInformer              cache.SharedIndexInformer
	profInformer             cache.SharedIndexInformer
	refreshQueue             workqueue.RateLimitingInterface
	argocdNamespace          string
	argocdInterlaceNamespace string
}

func Start(ctx context.Context, kubeConfigPath string, config *interlaceCfg.InterlaceConfig) {
	configBytes, _ := json.Marshal(config)
	log.Debugf("Interlace config: %s", string(configBytes))
	_, cfg, err := utils.GetK8sClient(kubeConfigPath)
	if err != nil {
		log.Fatalf("failed to get kubernetes config: %s", err.Error())
	}

	// appClientset := appClientset.NewForConfigOrDie(cfg)
	// if err != nil {
	// 	log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	// }
	// iProfClientset := iprofClientset.NewForConfigOrDie(cfg)
	// if err != nil {
	// 	log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	// }
	// appProvClientset := appprovClientset.NewForConfigOrDie(cfg)
	// if err != nil {
	// 	log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	// }

	interlaceNS := ""
	argocdNamespace := ""
	if config != nil {
		interlaceNS = config.ArgocdInterlaceNamespace
		argocdNamespace = config.ArgocdNamespace
	}

	c := newController(cfg, argocdNamespace, interlaceNS)
	c.Run(ctx)
}

func newController(kubeConfig *rest.Config, argocdNamespace, interlaceNS string) *controller {
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	ctrl := &controller{
		kubeConfig:               kubeConfig,
		refreshQueue:             q,
		argocdNamespace:          argocdNamespace,
		argocdInterlaceNamespace: interlaceNS,
	}

	var err error
	appClientset := appClientset.NewForConfigOrDie(kubeConfig)
	if err != nil {
		log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	}
	iProfClientset := iprofClientset.NewForConfigOrDie(kubeConfig)
	if err != nil {
		log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	}
	appProvClientset := appprovClientset.NewForConfigOrDie(kubeConfig)
	if err != nil {
		log.Fatalf("Error in starting argocd interlace controller: %s", err.Error())
	}

	appInformer := ctrl.newApplicationInformer(appClientset)
	appInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)

			app, ok := obj.(*appv1.Application)
			log.Debugf("create event for app `%s`", app.GetName())
			if ok {
				err := CreateEventHandler(app, iProfClientset, appProvClientset, interlaceNS, kubeConfig)
				if err != nil {
					log.Errorf("Error in handling create event: %s", err.Error())
				}
			}

			if err == nil {
				key = addKindToKey(ApplicationKind, key)
				ctrl.refreshQueue.Add(key)
			}

		},
		UpdateFunc: func(old, new interface{}) {
			if !ctrl.canProcessApp(old) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(old)
			oldApp, oldOK := old.(*appv1.Application)
			newApp, newOK := new.(*appv1.Application)
			if !oldOK || !newOK || !needReoncile(oldApp, newApp) {
				return
			}
			log.Debugf("update event for app `%s`", newApp.GetName())
			if oldOK && newOK {
				err := UpdateEventHandler(oldApp, newApp, iProfClientset, appProvClientset, interlaceNS, kubeConfig)
				if err != nil {
					log.Errorf("Error in handling update event: %s", err.Error())
				}
			}

			if err == nil {
				key = addKindToKey(ApplicationKind, key)
				ctrl.refreshQueue.Add(key)
			}

		},
		DeleteFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)

			if err == nil {
				log.Debug("Event received of type delete for key ", key)
				//ctrl.refreshQueue.Add(key)
			}

		},
	})

	profInformer := ctrl.newProfileInformer(iProfClientset)
	profInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !ctrl.canProcessProf(obj) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)

			prof, ok := obj.(*interlaceprofilev1beta1.InterlaceProfile)
			log.Debugf("profile `%s` created", prof.GetName())
			if ok {
				err := ProfileEventHandler(prof, appClientset, iProfClientset, appProvClientset, argocdNamespace, interlaceNS, kubeConfig)
				if err != nil {
					log.Errorf("Error in handling profile create event: %s", err.Error())
				}
			}

			if err == nil {
				key = addKindToKey(InterlaceProfileKind, key)
				ctrl.refreshQueue.Add(key)
			}

		},
		UpdateFunc: func(old, new interface{}) {
			if !ctrl.canProcessProf(old) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(old)
			_, oldOK := old.(*interlaceprofilev1beta1.InterlaceProfile)
			newProf, newOK := new.(*interlaceprofilev1beta1.InterlaceProfile)
			log.Debugf("profile `%s` updated", newProf.GetName())
			if oldOK && newOK {
				err := ProfileEventHandler(newProf, appClientset, iProfClientset, appProvClientset, argocdNamespace, interlaceNS, kubeConfig)
				if err != nil {
					log.Errorf("Error in handling profile update event: %s", err.Error())
				}
			}

			if err == nil {
				key = addKindToKey(InterlaceProfileKind, key)
				ctrl.refreshQueue.Add(key)
			}

		},
		DeleteFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)

			if err == nil {
				log.Debug("Event received of type delete for key ", key)
				//ctrl.profRefreshQueue.Add(key)
			}

		},
	})

	ctrl.appInformer = appInformer
	ctrl.profInformer = profInformer
	return ctrl
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

func (ctrl *controller) newProfileInformer(iProfClientset iprofClientset.Interface) cache.SharedIndexInformer {

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (apiruntime.Object, error) {
				return iProfClientset.InterlaceV1beta1().InterlaceProfiles(ctrl.argocdInterlaceNamespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return iProfClientset.InterlaceV1beta1().InterlaceProfiles(ctrl.argocdInterlaceNamespace).Watch(context.TODO(), options)
			},
		},
		&interlaceprofilev1beta1.InterlaceProfile{},
		0,
		cache.Indexers{},
	)
	return informer
}

func (c *controller) canProcessApp(obj interface{}) bool {
	_, ok := obj.(*appv1.Application)
	if ok {
		return ok
	}
	return false
}

func (c *controller) canProcessProf(obj interface{}) bool {
	_, ok := obj.(*interlaceprofilev1beta1.InterlaceProfile)
	if ok {
		return ok
	}
	return false
}

func (c *controller) Run(ctx context.Context) {

	defer utilruntime.HandleCrash() //this will handle panic and won't crash the process
	defer c.refreshQueue.ShutDown() //shutdown all workqueue and terminate all workers

	log.Info("Starting argocd-interlace...")

	go c.appInformer.Run(ctx.Done())
	go c.profInformer.Run(ctx.Done())

	log.Info("Synchronizing events...")

	//synchronize the cache before starting to process events
	if !cache.WaitForCacheSync(ctx.Done(), c.appInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync from app informer"))
		log.Info("synchronization failed...")
		return
	}

	//synchronize the cache before starting to process events
	if !cache.WaitForCacheSync(ctx.Done(), c.appInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync from prof informer"))
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
	log.Debug("Check if new events in queue ", c.refreshQueue.Len())

	keyIf, shutdown := c.refreshQueue.Get()
	key := keyIf.(string)
	log.Debugf("key from queue: %s", key)

	if shutdown {
		processNext = false
		return
	}

	processNext = true
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Recovered from panic: %+v\n%s", r, debug.Stack())
		}
		c.refreshQueue.Done(key)
	}()

	err := c.processItem(key)
	if err == nil {
		c.refreshQueue.Forget(key)
		return true
	}
	return true
}

func (c *controller) processItem(key string) error {
	kind, short_key := splitKindAndKey(key)
	var obj interface{}
	var exists bool
	var err error
	if kind == ApplicationKind {
		obj, exists, err = c.appInformer.GetIndexer().GetByKey(short_key)
	} else if kind == InterlaceProfileKind {
		obj, exists, err = c.profInformer.GetIndexer().GetByKey(short_key)
	}
	if err != nil {
		return fmt.Errorf("error fetching object with key %s from store: %v", key, err)
	}

	if !exists {
		// This happens after app was deleted, but the work queue still had an entry for it.
		return nil
	}
	var ok bool
	if kind == ApplicationKind {
		_, ok = obj.(*appv1.Application)
	} else if kind == InterlaceProfileKind {
		_, ok = obj.(*interlaceprofilev1beta1.InterlaceProfile)
	}
	if !ok {
		log.Warnf("Key '%s' in index is not an application", key)
		return nil
	}

	return nil
}

func addKindToKey(kind, key string) string {
	return fmt.Sprintf("%s:%s", kind, key)
}

func splitKindAndKey(key string) (string, string) {
	if strings.Contains(key, ":") {
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	return "", key
}

func needReoncile(oldApp, newApp *appv1.Application) bool {
	need := false
	if oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "Synced" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		need = true
	}
	return need
}
