## Authenticating to an OCI Registry

ArgoCD Interlacer requires to setup access credentials for your OCI image registry.

For example, if your OCI image registry is hosted in Google cloud, refer to [here](https://cloud.google.com/docs/authentication/getting-started) for setting up acccess credentials.

To access your image registry from ArgoCD Interlacer, setup a secret `argocd-interlace-gcr-secret` in namespace `argocd-interlace` with credentials as below.

Save the name of your OCI image registry information (email, path to the credential file) as environment variables:
```shell
export OCI_IMAGE_REGITSRY_EMAIL="your-email@gmail.com"
export OCI_CREDENTIALS_PATH="/home/image-registry-crendtials.json"
```

To configure secret `argocd-interlace-gcr-secret`, run:
```shell
kubectl create secret docker-registry argocd-interlace-gcr-secret\
 --docker-server "https://gcr.io" --docker-username _json_key\
 --docker-email "$OCI_IMAGE_REGITSRY_EMAIL"\
 --docker-password="$(cat ${OCI_CREDENTIALS_PATH} | jq -c .)"\
 -n argocd-interlace --dry-run=client -ojson | jq -r '.data.".dockerconfigjson"'| read output;\
     kubectl patch secret argocd-interlace-gcr-secret -n argocd-interlace\
     -p="{\"data\":{\".dockerconfigjson\": \"$output\"}}" -v=1
```

To update OCI Image Registry environment setting for ArgoCD Deployment, run by specifyng your OCI registry name:
```shell
kubectl set env deployment/argocd-interlace-controller  -n argocd-interlace OCI_IMAGE_REGISTRY=gcr.io/<some-registry-name>
```