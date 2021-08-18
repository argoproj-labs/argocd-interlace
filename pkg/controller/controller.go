package controller

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/gajananan/argocd-interlace/pkg/interlace"
	"github.com/gajananan/argocd-interlace/pkg/utils"

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
	applicationClientset appClientset.Interface
	informer             cache.SharedIndexInformer
	appRefreshQueue      workqueue.RateLimitingInterface
	namespace            string
}

func Start(ctx context.Context, config string, namespace string) {
	_, cfg, err := utils.GetClient(config)
	appClientset := appClientset.NewForConfigOrDie(cfg)
	if err != nil {
		log.Fatalf("error occured during starting argocd interlace controller", err.Error())
	}

	c := newController(appClientset, namespace)
	c.Run(ctx)
}

func (ctrl *controller) newApplicationInformer(applicationClientset appClientset.Interface) cache.SharedIndexInformer {

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (apiruntime.Object, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.namespace).Watch(context.TODO(), options)
			},
		},
		&appv1.Application{},
		0,
		cache.Indexers{},
	)
	return informer
}

func newController(applicationClientset appClientset.Interface, namespace string) *controller {
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	ctrl := &controller{
		applicationClientset: applicationClientset,
		appRefreshQueue:      q,
		namespace:            namespace,
	}

	appInformer := ctrl.newApplicationInformer(applicationClientset)
	appInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)
			/*
				app, ok := obj.(*appv1.Application)

				if ok {
					interlace.CreateEventHandler(app)
				}
			*/
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
				interlace.UpdateEventHandler(oldApp, newApp)
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
				log.Debug("Event received of type delete for key [%s] ", key)
				//ctrl.appRefreshQueue.Add(key)
			}

		},
	})

	ctrl.informer = appInformer
	return ctrl
}

func (c *controller) canProcessApp(obj interface{}) bool {
	_, ok := obj.(*appv1.Application)
	if !ok {
		return false
	}
	return true
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
	//Use a switch clause instead and process the events based on the type

	return nil
}
