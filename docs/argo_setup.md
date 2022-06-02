## Authenticating to ArgoCD RÉST API

ArgoCD Interlace requires REST API url and the bearer token ([See doc](setup_argocd_account.md) for setting up readonly access token) available in a secret called `argocd-config-secret`.

Save the base URL of ArgoCD REST API server and bearer token as an environment variables:

```shell
export ARGOCD_API_BASE_URL="https://argo-server-argocd.apps.<cluster-host-name>"
export ARGOCD_TOKEN=<your token>
```

To configure a secret `argocd-config-secret` with for ArgoCD credentials, run:
```shell
echo $ARGOCD_TOKEN | base64 | read output;\
     kubectl patch secret argocd-config-secret -n argocd-interlace\
     -p="{\"data\":{\"ARGOCD_TOKEN\": \"$output\"}}" -v=1

echo $ARGOCD_API_BASE_URL | base64 | read output;\
     kubectl patch secret argocd-config-secret -n argocd-interlace\
     -p="{\"data\":{\"ARGOCD_API_BASE_URL\": \"$output\"}}" -v=1
```