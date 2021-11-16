## Setting up Cosign Signing

ArgoCD Interlace uses [cosign](https://github.com/sigstore/cosign) for siging the manifest generated.

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

To configuure signing secrets, run:
```shell
cat $COSIGN_KEY | base64 | tr -d \\n | read output;\
    kubectl patch secret signing-secrets -n argocd-interlace -p="{\"data\":{\"cosign.key\": \"$output\"}}" -v=1

cat $COSIGN_PUB | base64 | tr -d \\n | read output;\
    kubectl patch secret signing-secrets -n argocd-interlace -p="{\"data\":{\"cosign.pub\": \"$output\"}}" -v=1
 ```

 After setting up all required secrets, restart argocd-interlace pod to make configurations to avaiable to Interlace.

 ```shell
 kubectl scale deploy argocd-interlace-controller -n argocd-interlace --replicas=0
 kubectl scale deploy argocd-interlace-controller -n argocd-interlace --replicas=1
 ```