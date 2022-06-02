#!/bin/bash

set -e

ARGOCD_NAMESPACE=$1
ARGOCD_ADMIN_USERNAME=$2
ARGOCD_ADMIN_PASSWORD=$3
SIGN_KEY_PATH=$4
VERIFY_KEY_PATH=$5

if [[ $SIGN_KEY_PATH == "" ]]; then
    SIGN_KEY_PATH=keys/cosign.key
fi
if [[ $VERIFY_KEY_PATH == "" ]]; then
    VERIFY_KEY_PATH=keys/pubring.gpg
fi

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

# configure argocd API token to `argocd-config-secret`
kubectl patch secret argocd-config-secret -n argocd-interlace -p="{\"data\":{\"ARGOCD_NAMESPACE\":\"$(echo -n $ARGOCD_NAMESPACE | base64)\",\"ARGOCD_USER\":\"$(echo -n $ARGOCD_ADMIN_USERNAME | base64)\",\"ARGOCD_USER_PWD\":\"$(echo -n $ARGOCD_ADMIN_PASSWORD | base64)\"}}"

# configure `argocd-interlace-keys`
kubectl patch secret argocd-interlace-keys -n argocd-interlace -p="{\"data\":{\"cosign.key\":\"$(cat $SIGN_KEY_PATH | base64)\",\"pubring.gpg\":\"$(cat $VERIFY_KEY_PATH | base64)\"}}"

