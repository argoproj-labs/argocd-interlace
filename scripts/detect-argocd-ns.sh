#!/bin/bash

set -e

if ! [ -x "$(command -v kubectl)" ]; then
    echo 'Error: kubectl is not installed.' >&2
    exit 1
fi

nslist=$(kubectl get ns 2>/dev/null | awk '{print $1}' | grep -E -e "^argocd$" -e "^openshift-gitops$" || true)

IFS=$'\n'
for item in $(echo -e "$nslist"); do
    ns_name=$(echo $item | sed 's/\\n//g')
    podnum=$(kubectl get pod -n $ns_name 2>/dev/null | grep application-controller-0 | grep Running | wc -l)
    if [ $podnum -eq 1 ]; then
        echo "$ns_name"
        exit 0
    fi
done

echo 'Error: ArgoCD controller pod is not found both in "argocd" and "openshift-gitops" namespaces.' >&2
echo '       Please specify the ArgoCD namespace.' >&2
exit 1
