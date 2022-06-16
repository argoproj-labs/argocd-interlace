#!/bin/bash

set -e

ARGOCD_NS=$1

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

secrets=$(kubectl get secret -n $ARGOCD_NS 2>/dev/null | awk '{print $1}')

secnum1=$(echo -e "$secrets" | sed 's/\n//g' | grep -E "^argocd-initial-admin-secret$" | wc -l)
if [ $secnum1 -eq 1 ]; then
    echo "argocd"
    exit 0
fi

secnum2=$(echo -e "$secrets" | sed 's/\n//g' | grep -E "^openshift-gitops-cluster$" | wc -l)
if [ $secnum2 -eq 1 ]; then
    echo "openshift-gitops"
    exit 0
fi


