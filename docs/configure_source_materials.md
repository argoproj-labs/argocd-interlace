### Configure source materials

ArgoCD Interlace requires a user to 

- add [signature-secret.yaml] below in source material repo (name must be configured). 

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: <application_name>
  annotations:
    argocd.interlace.dev/signature-resource: "true"
    argocd.interlace.dev/message-compress: "true"
  type: Opaque
```

- edit [kustomization.yaml] in thee source material repo to add signature-secret.yaml
