### Setup Readonly User Account in ArgoCD

Using `argocd cli`,  login to an argocd deployment

Below is a sample command to login to ArgoCD in a cluster hosted in localhost.
```
argocd login localhost:8080
WARNING: server certificate had error: x509: certificate is valid for localhost, argocd-server, argocd-server.argocd, argocd-server.argocd.svc, argocd-server.argocd.svc.cluster.local, not argocd.local. Proceed insecurely (y/n)? y
Username: admin
Password:
'admin:login' logged in successfully
Context 'localhost:8080' updated
```

Note: You may need to port forward to ArgoCD server

```
 kubectl port-forward svc/argocd-server -n argocd 8080:443
```


Configure `argocd-cm` in `argocd` namespace to add user account wiht readonly access to API

```
kubectl edit cm -n argocd argocd-cm -oyaml
```

Below is a sample that shows `readonlyuser`  with access to `apiKey,login` is enabled
```yaml
apiVersion: v1
data:
  accounts.readonlyuser: apiKey,login
  accounts.readonlyuser.enabled: "true"
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd 
```

Configure RBAC for restricting to readonly access
```
k edit cm -n argocd argocd-rbac-cm -oyaml
```

```yaml
apiVersion: v1
data:
  policy.csv: |
    p, role:readonly, applications, get, */*, allow
    g, readonlyuser, role:readonly
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
```

Change the password for the account `readonlyuser`
```
argocd account update-password --account readonlyuser

*** Enter current password:
*** Enter new password:
*** Confirm new password:
```

Get the Bearer token for account `readonlyuser`

```
export ARGOCD_SERVER=https://argocd.local:8080
export PASSWORD=<Password that you setup earlier>
export ARGOCD_TOKEN=$(curl -k $ARGOCD_SERVER/api/v1/session -d "{\"username\":\"readonlyuser\",\"password\": \"$PASSWORD\"}" | jq . -c | jq ."token" | tr -d '"')
echo $ARGOCD_TOKEN
```


