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

(Optional) If you want to setup argocd-interlace with your existing keys, do [Key Setup](docs/key_setup.md) and `make deploy` again.

To verify that installation was successful, ensure Status of pod `argocd-interlace-controller` become `Running`:
```shell
$ kubectl get pod -n argocd-interlace -w
NAME                                              READY   STATUS    RESTARTS   AGE
pod/argocd-interlace-controller-f57fd69fb-72l4h   1/1     Running   0          19m
```

### Usage

1. Deploy ArgoCD and ArgoCD Interlace with your keys.

    Follow the [Installation](#installation) section.

1. Sign your source material repository.

    Generate signatures using the signing script.

    ```
    $ ./scripts/sign-source-repo.sh <PATH/TO/SOURCE_MATERIAL_REPO>
    ```

    Then 2 files `source-materials` and `source-materials.sig` should be generated, and push them to your remote repository.

1. Create ArgoCD Application which uses the signed source materials.

    ```
    $ kubectl create -n argocd -f <PATH/TO/YOUR/APPLICATION>
    ```

    This is a normal ArgoCD step.

1. Check annotations in the Application.

    Then you can get the latest provenance data as below.

    ```
    $ kubectl get application <APPLICATION/NAME> -n <APPLICATION/NAMESPACE> -o jsonpath='{.metadata.annotations.interlace\.argocd\.dev/provenance}' | base64 -d | jq .
    {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://slsa.dev/provenance/v0.1",
        "subject": [
            {
                "name": "/tmp/output/sample-app/manifest.yaml",
                "digest": {
                    "sha256": "72d33174b97b178a035a16f04518ff971b1edb3d1b603c858f11e0f12befb8ca"
                }
            }
        ],
    ...
        "predicate": {
            ...
            "materials": [
                {
                    "uri": "https://github.com/hirokuni-kitahara/sample-kustomize-app.git",
                    "digest": {
                    "commit": "0ff5408670b90b4a7ca69ca3829aa37e1acb39db",
                    "path": "./",
                    "revision": "master"
                    }
                }
            ]
        }
    }
    ```

    `subject` field in the provenance contains the digest value of the generated manifest, and `materials` is a list of source material repositories with commit ID.

    Also, you can checkl the detail information of the provenance in the log.
    ```
    $ kubectl logs -n argocd-interlace deployment.apps/argocd-interlace-controller
    ...
    time="2022-03-07T09:01:32Z" level=info msg="[INFO][sample-app] Created entry at index 1579738, available at: https://rekor.sigstore.dev/api/v1/log/entries/7ab813bb62f0d87ad7191856bd12fb8b640ca75a797169265cdc813bb435108f\n"
    ```

### Customize Settings

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