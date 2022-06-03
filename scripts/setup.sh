#!/bin/bash

set -e

ARGOCD_NAMESPACE=$1
ARGOCD_API_USERNAME=$2
ARGOCD_API_PASSWORD=$3
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
kubectl patch secret argocd-config-secret -n argocd-interlace -p="{\"data\":{\"argocdNamespace\":\"$(echo -n $ARGOCD_NAMESPACE | base64)\",\"argocdAPIUser\":\"$(echo -n $ARGOCD_API_USERNAME | base64)\",\"argocdAPIPassword\":\"$(echo -n $ARGOCD_API_PASSWORD | base64)\"}}"

# configure `argocd-interlace-keys`
kubectl patch secret argocd-interlace-keys -n argocd-interlace -p="{\"data\":{\"signKey\":\"$(cat $SIGN_KEY_PATH | base64)\",\"verifyKey\":\"$(cat $VERIFY_KEY_PATH | base64)\"}}"

