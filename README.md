# ArgoCD Interlace

ArgoCD is widely used for enabling CD GitOps. ArgoCD internally builds manifest from source data in Git repository, and auto-sync it with target clusters. 

ArgoCD Interlace enhances ArgoCD capability from end-to-end software supply chain security viewpoint. Interlace adds authenticity of the manifest and the traceability to the source to ArgoCD.

ArgoCD Interlace works as a Kubernetes Custom Resource Definition (CRD) controller. Interlace monitors the trigger from state changes of Application resources on the ArgoCD cluster. When detecting new manifest build, Interlace sign the manifest, record the detail of manifest build such as the source files for the build, the command to produce the manifest for reproducibility. Interlace stores those details as provenance records in in-toto format. 

![ArgoCD-Interlace-Arch](./images/argocd-interlace-arch.png)


The features are 
- Pluggable to ArgoCD
- Capture manifest and provenance from application.status automatically
- Sign manifest
- Record provenance in intoto format

<<<<<<< HEAD
[Quick Start](docs/quick_start.md)
=======
>>>>>>> 188918efd522372397e083cb031c1d991cdf51cd

 Demo
 ![intro](images/intro.gif?)