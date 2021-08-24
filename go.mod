module github.com/IBM/argocd-interlace

go 1.16

require (
	github.com/argoproj/argo-cd/v2 v2.0.5
	github.com/go-git/go-billy/v5 v5.3.1
	github.com/go-git/go-git/v5 v5.4.2
	github.com/go-redis/redis/v8 v8.11.1 // indirect
	github.com/google/go-containerregistry v0.5.1
	github.com/in-toto/in-toto-golang v0.2.1-0.20210627200632-886210ae2ab9
	github.com/sigstore/cosign v1.0.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210823063824-c4245c9ae5b0
	github.com/sigstore/rekor v0.3.0
	github.com/sigstore/sigstore v0.0.0-20210726180807-7e34e36ecda1
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/theupdateframework/go-tuf v0.0.0-20210722233521-90e262754396
	github.com/tidwall/gjson v1.8.1
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/apiserver v0.21.3 // indirect
	k8s.io/cli-runtime v0.21.3 // indirect
	k8s.io/client-go v11.0.1-0.20190816222228-6d55c1b1f1ca+incompatible
	k8s.io/component-base v0.21.3 // indirect
	k8s.io/kube-aggregator v0.21.3 // indirect
	k8s.io/kubectl v0.21.3 // indirect
	k8s.io/kubernetes v1.21.0 // indirect
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/docker/distribution => github.com/distribution/distribution v2.7.1+incompatible
	github.com/docker/docker => github.com/moby/moby v0.7.3-0.20190826074503-38ab9da00309
	github.com/IBM/argocd-interlace => ./
	github.com/sigstore/cosign => github.com/sigstore/cosign v1.0.1-0.20210728181701-5f1f18426dc3
	k8s.io/api => k8s.io/api v0.21.2

	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.21.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.2-rc.0
	k8s.io/apiserver => k8s.io/apiserver v0.21.2
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.21.2
	k8s.io/client-go => k8s.io/client-go v0.21.2
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.21.2
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.21.2
	k8s.io/code-generator => k8s.io/code-generator v0.21.2-rc.0
	k8s.io/component-base => k8s.io/component-base v0.21.2
	k8s.io/component-helpers => k8s.io/component-helpers v0.21.2
	k8s.io/controller-manager => k8s.io/controller-manager v0.21.2
	k8s.io/cri-api => k8s.io/cri-api v0.21.2-rc.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.21.2
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.21.2
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.21.2
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.21.2
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.21.2
	k8s.io/kubectl => k8s.io/kubectl v0.21.2
	k8s.io/kubelet => k8s.io/kubelet v0.21.2
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.21.2
	k8s.io/metrics => k8s.io/metrics v0.21.2
	k8s.io/mount-utils => k8s.io/mount-utils v0.21.2-rc.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.21.2
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.21.2
	k8s.io/sample-controller => k8s.io/sample-controller v0.21.2
)
