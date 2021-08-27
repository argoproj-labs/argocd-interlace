# Authentication for ArgoCD Interlace

ArgoCD Interlacer
* generates OCI images that need to be pushed an image Registry.
* access ArgoCD REST API to build manifest for an application
* requires signing keys for creating signature for manifest generated.

## Authenticating to an OCI Registry

ArgoCD Interlacer requires to setup access credentials for your OCI image registry.

For example, if your OCI image registry is hosted in Google cloud, refer to [here](https://cloud.google.com/docs/authentication/getting-started) for setting up acccess credentials.

To access your image registry from ArgoCD Interlacer, setup a secret `argocd-interlace-gcr-secret` in namespace `argocd-interlace` with credentials as below and give ArgoCD Interlace service account access to the secret.

Save the name of your OCI image registry information (email, path to the credential file) as environment variables:
```shell
OCI_IMAGE_REGITSRY_EMAIL="your-email@gmail.com"
OCI_CREDENTIALS_PATH="/home/image-registry-crendtials.json"
```

To create secret, run:
```shell
kubectl apply secret docker-registry argocd-interlace-gcr-secret\
 --docker-server "https://gcr.io" --docker-username _json_key\
 --docker-email "$OCI_IMAGE_REGITSRY_EMAIL"\
 --docker-password="$(cat ${OCI_CREDENTIALS_PATH} | jq -c .)"\
 -n argocd-interlace
```

Make ArgoCD Interlace service account have access to secret above

```shell
kubectl patch serviceaccount argocd-interlace-controller \
  -p "{\"imagePullSecrets\": [{\"name\": \"argocd-interlace-gcr-secret\"}]}" -n argocd-interlace
```

To update OCI Image Registry environment setting for ArgoCD Deployment, run by specifyng your OCI registry name:
```shell
kubectl set env deployment/argocd-interlace-controller OCI_IMAGE_REGISTRY=gcr.io/<some-registry-name>
```

## Authenticating to ArgoCD RÉST API

ArgoCD Interlace requires REST API url and the bearer token (readonly access) available in a secret called `argocd-token-secret`.

Save the base URL of ArgoCD REST API server and bearer token as an environment variables:

```shell
export ARGOCD_API_BASE_URL="https://argo-server-argocd.apps.<cluster-host-name>"
export ARGOCD_TOKEN=<your token>
```

To create a secret with for ArgoCD credentials, run:
```shell
kubectl apply secret generic argocd-token-secret\
 --from-literal=ARGOCD_TOKEN=${ARGOCD_TOKEN}\
 --from-literal=ARGOCD_API_BASE_URL=${ARGOCD_API_BASE_URL}\
 -n argocd-interlace
```

## Setting up Cosign Signing

ArgoCD Interlace uses [cosign](https://github.com/sigstore/cosign) for siging the manifest generated as an OCI image.

To create a cosign keypair, `cosign.key` and `cosign.pub`, install cosign and run the following:
```shell
cosign generate-key-pair
```
Provide a password when cosign prompt for it.

ArgoCD Interlace requiress the encrypted private key (`cosign.key`) available in a secret called `signing-secrets` with the following data:

* `cosign.key` (the cosign-generated private key)
* `cosign.pub` (the cosign-generated public key)

Save cosign key pairs to environment variables:
```shell
COSIGN_KEY=./cosign.key
COSIGN_PUB=./cosign.pub
```

To create signing secrets, run:
```shell
kubectl apply secret generic signing-secrets\
 --from-file=cosign.key="${COSIGN_KEY}"\
 --from-file=cosign.password="${COSIGN_PUB}"\
 -n argocd-interlace
 ```