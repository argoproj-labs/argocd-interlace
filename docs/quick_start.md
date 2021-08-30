# Quick Start

ArgoCD Interlace runs in parallel to an existing ArgoCD deployment in a plugable manner in a cluster.  

Interlace monitors the trigger from state changes of `Application` resources managed by ArgoCD. 

For an application, when detecting new manifest build by ArgoCD, Interlace retrives the latest manifest via REST API call to ArgoCD server, signs the manifest and store it as OCI image in a registry, record the detail of manifest build such as the source files for the build, the command to produce the manifest for reproducibility. Interlace stores those details as provenance records in [in-toto](https://in-toto.io) format and upload it to [Sigstore](https://sigstore.dev/)log for verification.

### Installation
Prerequisite: Install [ArgoCD](https://argo-cd.readthedocs.io/en/stable/getting_started/) on your Kubernetes cluster before you install ArgoCD Interlace.


To install the latest version of ArgoCD Interlace to your cluster, run:
```
kubectl apply --filename https://raw.githubusercontent.com/IBM/argocd-interlace/main/releases/release.yaml
```
This creates a default installation of ArgoCD Interlace, however you will need futher setup for seeing it in action.

To verify that installation was successful, ensure Status of pod `argocd-interlace-controller` become `Running`:
```shell
$ kubectl get pod -n argocd-interlace -w
NAME                                              READY   STATUS    RESTARTS   AGE
pod/argocd-interlace-controller-f57fd69fb-72l4h   1/1     Running   0          19m
```

### Setup

To complete setting up ArgoCD Interlace, please follow the steps in [doc](setup.md) to configure the followings: 
* OCI image registry authentication
* ArgoCD REST API authentication
* Cosign based signing keys


## Example Scenario
To see ArgoCD Interlace in action, check the [example scenario](example_scenario.md).