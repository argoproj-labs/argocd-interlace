# ArgoCD Interlace

ArgoCD Interlace runs in parallel to an existing ArgoCD deployment in a plugable manner in a cluster.  

Interlace monitors the trigger from state changes of `Application` resources managed by ArgoCD. 

For an application, when detecting new manifest build by ArgoCD, Interlace retrives the latest manifest via REST API call to ArgoCD server, signs the manifest and store it as OCI image in a registry, record the detail of manifest build such as the source files for the build, the command to produce the manifest for reproducibility. Interlace stores those details as provenance records in [in-toto](https://in-toto.io) format and upload it to [Sigstore](https://sigstore.dev/)log for verification.


## Prerequisites
- ArgoCD already deployed in a cluster

## Install

### Retrive the source from `ArgoCD Interlace` Git repository.

git clone this repository and moved to `argocd-interlace` directory

```
$ git clone https://github.com/IBM/argocd-interlace.git
$ cd argocd-interlace
$ pwd /home/repo/argocd-interlace
```

### Prepare namespace for installing ArgoCD Interlace

```
kubectl create ns argocd-interlace
```

### Setup secrets

1. You will need access to credentials for your OCI image registry (they are in a file called image-registry-credentials.json in this example)

For example, if your OCI image registry is hosted in Google cloud, refer to [here](https://cloud.google.com/docs/authentication/getting-started) for setting up acccess credentials.


To access your image registry from ArgoCD Interlacer
- Change env setting `OCI_IMAGE_REGISTRY` in deploy/patch.yaml to your OCI image registry (e.g. "gcr.io/your-image-registry").

- Setup a secret `argocd-interlace-gcr-secret` in namespace `argocd-interlace` with credentials as below. 


Create secret with the following command:
```
OCI_IMAGE_REGITSRY_EMAIL="your-email@gmail.com"
OCI_CREDENTIALS_PATH="/home/image-registry-crendtials.json"

kubectl create secret docker-registry argocd-interlace-gcr-secret\
 --docker-server "https://gcr.io" --docker-username _json_key\
 --docker-email "$OCI_IMAGE_REGITSRY_EMAIL"\
 --docker-password="$(cat ${OCI_CREDENTIALS_PATH} | jq -c .)"\
 -n argocd-interlace
```

2. You will need access to credentials for your ArgoCD deployment. 

Create a secret that contains `ARGOCD_TOKEN` and `ARGOCD_API_BASE_URL` to create access to your ArgoCD REST API.

See [here](https://argo-cd.readthedocs.io/en/stable/operator-manual/user-management/#local-usersaccounts-v15) for setting up a user account with readonly access in ArgoCD

A sample set of steps to create user account with readonly access and to retrive `ARGOCD_TOKEN` in ArgoCD is described [here](./SETUP_ARGOCD_USER_ACCOUNT.md)

Retrive a token for your user account in ArgoCD

```
export ARGOCD_API_BASE_URL="https://argo-route-argocd.apps.<cluster-host-name>"
export PASSWORD=<>
export ARGOCD_TOKEN=$(curl -k $ARGOCD_SERVER/api/v1/session -d "{\"username\":\"admin\",\"password\": \"$PASSWORD\"}" | jq . -c | jq ."token" | tr -d '"')
```

Create a secret with the retrived token and base url:
```
kubectl create secret generic argocd-token-secret\
 --from-literal=ARGOCD_TOKEN=${ARGOCD_TOKEN}\
 --from-literal=ARGOCD_API_BASE_URL=${ARGOCD_API_BASE_URL}\
 -n argocd-interlace
```

3. Create `cosign` key pairs for creating signatures for generated manifests by ArgoCD Interlace

You will need to setup a key pair for signing manifest. In this example, you will need [cosign](https://github.com/sigstore/cosign) 

```
mkdir cosign-keys
cd cosign-keys
cosign generate-key-pair
Enter password for private key:
Enter again:
```

Confirm two files were generated correctly
```
ls cosign-keys
cosign.key
cosign.pub
```

Setup a secret `signing-secrets` that contains the key pairs in `argocd-interlace` namespace.

```
COSIGN_KEY=./cosign.key
COSIGN_PUB=./cosign.pub

kubectl create secret generic signing-secrets\
 --from-file=cosign.key="${COSIGN_KEY}"\
 --from-file=cosign.pub="${COSIGN_PUB}"\
 -n argocd-interlace
```


### Install Argocd Interlace

Execute the following command to deploy ArgoCD Interlace to the cluster where  ArgoCD is deployed.

```
kubectl apply --filename https://raw.githubusercontent.com/IBM/argocd-interlace/main/releases/release.yaml
```

You can check after the successful deployment of ArgoCD Interlace. A pod that represents ArgoCD Interlacer should be running as below.

```
kubectl get pod -n argocd-interlace
NAME                                              READY   STATUS    RESTARTS   AGE
pod/argocd-interlace-controller-f57fd69fb-72l4h   1/1     Running   0          19m
```


### A sample Scenario that demonstrate ArgoCD Interlacer's capability 

Check how ArogCD Interlacer works vai a sample application. 
- Create application resource in ArgoCD
- ArgoCD Interlace performs the steps, when detecting new application creation or changes in an already deployed application
    - retrive latest manifest for application
    - sign manifest
    - create provenance record (such as the source files for the build, the command to produce the manifest for reproducibility)

1. Use the following helloworld sample applicaiton.

https://github.com/kubernetes-sigs/kustomize/tree/master/examples/helloWorld

2.  Confgure helloworld sample applicaiton in your ArgoCD deployment

- Create a namespace `helloworld-ns`
- Fill in the cluster information for `server` under `destination` section as shown below before creating application resource.

E.g.: application-helloworld.yaml 

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: app-helloworld
  namespace: argocd
spec:
  destination:
    namespace: helloworld-ns
    server: <your-cluster>
  project: default
  source:
    path: examples/helloWorld/
    repoURL: https://github.com/kubernetes-sigs/kustomize
    targetRevision: master
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

Create application with the folllowing command
```
kubectl create -n argocd -f application-helloworld.yaml
```

Argocd Interlacer detects the trigger from state changes of Application resources on the ArgoCD cluster when creating the above sample application.
Interlacer 
 - retrive the latest manifest for the sample application by querying ArgoCD rest API. The latest manifest containes the specification of resources managed for the sample application by ArgoCD.  
 - sign the manifest and store it as an OCI image in the configured registry
 - record the detail of manifest build such as the source files for the build, the command to produce the manifest for reproducibility. Interlace stores those details as provenance records in in-toto format. 


3.  You can find manifest image with signature in the OCI registry

```
gcr.io/some-image-registry/<image-prefix>-app-helloworld:<sometag>
```


4.  You can verify provenance record generated by ArgoCD Interlacer as follows

Set up [k8s-manifest-sigstore](https://github.com/sigstore/k8s-manifest-sigstore) CLI for verifying the manifest signature and provenance record generated by ArgoCD Interlace.


Setup configuration file required for `k8s-manifest-sigstore` CLI.
E.g.: cosign-keys/config-helloworld.yaml
```
ignoreFields:
  - objects:
    - kind: Service
    fields:
    - "metadata.finalizers"
  - objects:
    - kind: Route
    fields:
    - spec.host

```

Using `k8s-manifest-sigstore` CLI, verify the signature and provenace of resources for the sample application as shown below:

Pass the following parameters
- `-n`: namespace where the sample application is deployed by ArgoCD
- `i`: refers to OCI image generated by ArgoCD Interlace for the sample application
- `k`: refers to the cosign public key generated earlier.

E.g.: Successfull validation by `verify-resource`  command via [`k8s-manifest-sigstore`] CLI will generate a sample output like below.

```
kubectl sigstore verify-resource -n helloworld-ns\
      -i gcr.io/some-image-registry/<image-prefix>-app-helloworld:<sometag>\
      -k cosign-keys/cosign.pub --provenance

[SUMMARY]
TOTAL   VALID   INVALID
3       3       0

[MANIFESTS]
NAME                                                              SIGNED   SIGNER
gcr.io/some-image-registry/<image-prefix>-app-helloworld:<sometag>   true     N/A

[RESOURCES]
KIND         NAME             VALID   ERROR   AGE
ConfigMap    the-map          true            22h
Service      the-service      true            22h
Deployment   the-deployment   true            22h

[RESOURCES - PODS/CONTAINERS]
POD                              CONTAINER       IMAGE ID
the-deployment-74f98c845-cg597   the-container   docker.io/monopole/hello@sha256:c8273383d314bfb945f5a879559599990f055da92ee078bf0f960e006c8ebe8b
the-deployment-74f98c845-qrzg2   the-container   docker.io/monopole/hello@sha256:c8273383d314bfb945f5a879559599990f055da92ee078bf0f960e006c8ebe8b
the-deployment-74f98c845-vb8wh   the-container   docker.io/monopole/hello@sha256:c8273383d314bfb945f5a879559599990f055da92ee078bf0f960e006c8ebe8b

[PROVENANCES - ATTESTATIONS]
ARTIFACT                 gcr.io/kg-image-registry/argocd.apps.ma4kmc2-akmebank-app-stage-cl1:mnf
MATERIALS 1   URI        https://github.com/kubernetes-sigs/kustomize
              COMMIT     0bb9beb2e79ece9805aa62620c1bde309e644f49
              PATH       examples/helloWorld/
              REVISION   master
To get this attestation: curl -s "https://rekor.sigstore.dev/api/v1/log/entries/?logIndex=686609"
```