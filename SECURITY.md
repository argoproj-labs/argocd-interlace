# Security Policy for ArgoCD Interlace

## Preface

ArgoCD Interlace is a pluggable Application controller that enables software supply chain security in ArgoCD's GitOps mechanism by adding authenticity of the manifest and the traceability to the source materials.

To read some ArgoCD configurations, ArgoCD Interlace creates a ClusterRole with a read only permission for ArgoCD resources. This is only for reading configurations and it does not require any write permission for ArgoCD resourcs.

## Security Scans

We use the static code analysis tool, golangci-lint, for compile time linting.

This is run on each pull request and before each release.

Additionally, Dependabot is configured to scan and report new security vulnerabilities in our dependancy tree on a daily basis.


## Reporting a Vulnerability

If you find a security related bug in ArgoCD Interlace, we kindly ask you 
for responsible disclosure and for giving us appropriate time to react, 
analyze and develop a fix to mitigate the found security vulnerability.

Please report vulnerabilities by e-mail to the following address: 

* muew@jp.ibm.com

All vulnerabilities and associated information will be treated with full confidentiality. 

## Public Disclosure

Security vulnerabilities will be disclosed via release notes and using the
[GitHub Security Advisories](https://github.com/argoproj-labs/argocd-interlace/security/advisories)
feature to keep our community well informed, and will credit you for your findings (unless you prefer to stay anonymous, of course).