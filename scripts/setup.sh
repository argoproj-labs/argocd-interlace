#!/bin/bash

set -e

ARGOCD_NAMESPACE=$1
USE_EXAMPLE_KEYS=$2

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v argocd)" ]; then
    echo 'Error: argocd is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v jq)" ]; then
    echo 'Error: jq is not installed.' >&2
    exit 1
fi

if ! [ -x "$(command -v cosign)" ]; then
    # try installing by go install command 
    go install github.com/sigstore/cosign/cmd/cosign@v1.5.2 || true
    if ! [ -x "$(command -v cosign)" ]; then
        echo 'Error: cosign is not installed.' >&2
        exit 1
    fi
fi

if ! [ -x "$(command -v gpg)" ]; then
    echo 'Error: gpg is not installed.' >&2
    exit 1
fi


# port-forward
kubectl port-forward svc/argocd-server -n argocd 8080:443 > /dev/null 2>&1 & 

argoServerURL=localhost:8080

# get password
argoLoginPass=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)

# login
echo y | argocd login $argoServerURL --username admin --password $argoLoginPass

# add user account 'readonlyuser'
kubectl patch cm -n argocd argocd-cm -p '{"data":{"accounts.readonlyuser":"apiKey,login","accounts.readonlyuser.enabled":"true"}}'

# set RBAC for the `readonlyuser`
kubectl patch cm -n argocd argocd-rbac-cm -p '{"data":{"policy.csv":"p, role:readonly, applications, get, */*, allow\ng, readonlyuser, role:readonly"}}'

# set password for the `readonlyuser`
readonlyuserPass="readonlyuser"
argocd account update-password --account readonlyuser --current-password $argoLoginPass --new-password $readonlyuserPass

# get API TOKEN
argoAPIToken=$(curl -sk https://$argoServerURL/api/v1/session -d "{\"username\":\"readonlyuser\",\"password\": \"$readonlyuserPass\"}" | jq . -c | jq -r ."token")

# configure argocd API token to `argocd-token-secret`
inclusteEndpoint="https://argocd-server.$ARGOCD_NAMESPACE.svc.cluster.local"
kubectl patch secret argocd-token-secret -n argocd-interlace -p="{\"data\":{\"ARGOCD_TOKEN\":\"$(echo $argoAPIToken | base64)\",\"ARGOCD_API_BASE_URL\":\"$(echo $inclusteEndpoint | base64)\",\"ARGOCD_PWD\":\"$argoLoginPass\"}}"

keysDir="./keys"
if [[ $USE_EXAMPLE_KEYS == "true" ]]; then
    keysDir="./examples/keys"
fi

cosignKeyName="$keysDir/cosign.key"
cosignPubkeyName="$keysDir/cosign.pub"
if [ ! -f $cosignKeyName ]; then
    orgDir=$(pwd)
    cd $keysDir
    COSIGN_PASSWORD="" cosign generate-key-pair
    cd $orgDir
fi

# configure `signing-secrets`
kubectl patch secret signing-secrets -n argocd-interlace -p="{\"data\":{\"cosign.key\":\"$(cat $cosignKeyName | base64)\",\"cosign.pub\":\"$(cat $cosignPubkeyName | base64)\"}}"

pubringName="$keysDir/pubring.gpg"
if [ ! -f $pubringName ]; then
    gpg --export --output $pubringName
fi

# configure `keyring-secret`
kubectl patch secret keyring-secret -n argocd-interlace -p="{\"data\":{\"pubring.gpg\":\"$(cat pubring.gpg | base64)\"}}"

# restart argocd interlace pod
kubectl scale deploy argocd-interlace-controller -n argocd-interlace --replicas=0
kubectl scale deploy argocd-interlace-controller -n argocd-interlace --replicas=1
