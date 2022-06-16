#!/bin/bash

set -e

ARGOCD_NAMESPACE=$1
SIGN_KEY_PATH=$2
VERIFY_KEY_PATH=$3
ARGOCD_API_USERNAME=$4
ARGOCD_API_PASSWORD=$5

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

userinfo=""
if [[ $ARGOCD_API_USERNAME != "" ]]; then
    if [[ $ARGOCD_API_PASSWORD != "" ]]; then
        userinfo=",\"argocdAPIUsername\":\"$(echo -n $ARGOCD_API_USERNAME | base64)\",\"argocdAPIPassword\":\"$(echo -n $ARGOCD_API_PASSWORD | base64)\""
    fi
fi

# configure argocd API token to `argocd-config-secret`
kubectl patch secret argocd-config-secret -n argocd-interlace -p="{\"data\":{\"argocdNamespace\":\"$(echo -n $ARGOCD_NAMESPACE | base64)\"$(echo -n $userinfo)}}"

# configure `argocd-interlace-keys`
kubectl patch secret argocd-interlace-keys -n argocd-interlace -p="{\"data\":{\"signKey\":\"$(cat $SIGN_KEY_PATH | base64)\",\"verifyKey\":\"$(cat $VERIFY_KEY_PATH | base64)\"}}"

