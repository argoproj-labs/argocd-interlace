# ArgoCD Interlace

ArgoCD is widely used for enabling CD GitOps. ArgoCD internally builds manifest from source data in Git repository, and auto-sync it with target clusters. 

ArgoCD Interlace enhances ArgoCD capability from end-to-end software supply chain security viewpoint. Interlace adds authenticity of the manifest and the traceability to the source to ArgoCD.

ArgoCD Interlace works as a Kubernetes Custom Resource Definition (CRD) controller. Interlace monitors the trigger from state changes of Application resources on the ArgoCD cluster. When detecting new manifest build, Interlace sign the manifest, record the detail of manifest build such as the source files for the build, the command to produce the manifest for reproducibility. Interlace stores those details as provenance records in [in-toto](https://in-toto.io) format and upload it to [Sigstore](https://sigstore.dev/) log for verification.

![ArgoCD-Interlace-Arch](./images/argocd-interlace-arch.png)


The features are 
- Pluggable to ArgoCD
- Verify signature of source materials used for generating manifest
- Capture manifest and provenance from application.status automatically
- Sign manifest
- Record provenance in in-toto format

### Installation
Prerequisite: Install [ArgoCD](https://argo-cd.readthedocs.io/en/stable/getting_started/) on your Kubernetes cluster before you install ArgoCD Interlace.


To install ArgoCD Interlace, run:
```
$ git clone https://github.com/IBM/argocd-interlace.git
$ cd argocd-interlace
$ make deploy
```
This automates install and setup with default configuration.

To verify that installation was successful, ensure Status of pod `argocd-interlace-controller` become `Running`:
```shell
$ kubectl get pod -n argocd-interlace -w
NAME                                              READY   STATUS    RESTARTS   AGE
pod/argocd-interlace-controller-f57fd69fb-72l4h   1/1     Running   0          19m
```

### Usage

To try ArgoCD Interlace, you can deploy the sample Application:
```
$ kubectl create -f examples/signed-application.yaml
```

Then you can see the provenance record ID and its URL in the log.
```
$ kubectl logs -n argocd-interlace deployment.apps/argocd-interlace-controller

...

time="2022-03-07T09:01:32Z" level=info msg="[INFO][sample-app] Created entry at index 1579738, available at: https://rekor.sigstore.dev/api/v1/log/entries/7ab813bb62f0d87ad7191856bd12fb8b640ca75a797169265cdc813bb435108f\n"
```

### Setup

To customize settings of ArgoCD Interlace, you can follow these documents:
* [ArgoCD REST API authentication for querying ArgoCD REST API to retrive desired manifest for an application](docs/argo_setup.md)
* [Configuring source material repository](docs/configure_source_materials.md)
* [Signing source materials](docs/configure_source_materials.md)
* [Cosign based signing keys for creating signature for desired manifest.](docs/signing_key_setup.md)
* [Verification key setup for verifying source materials](docs/verification_key_setup.md)


## Example Scenario
To see ArgoCD Interlace in action, check the [example scenario](docs/example_scenario.md).


 ### Demo
 ![intro](images/intro.gif?)