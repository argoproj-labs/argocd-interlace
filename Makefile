NAME=quay.io/gajananan/argocd-interlace-controller

VERSION=dev
TMP_DIR=/tmp/

.PHONY: build build-cli build-core, deploy, delete

build-linux:
	@echo building binary for image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)
	yq w -i  deploy/deployment.yaml 'spec.template.spec.containers.(name==argocd-interlace-controller).image' $(NAME):$(VERSION)

build-image:
	@echo building image
	docker build -t $(NAME):$(VERSION) .
	docker push $(NAME):$(VERSION)
	yq w -i  deploy/deployment.yaml 'spec.template.spec.containers.(name==argocd-interlace-controller).image' $(NAME):$(VERSION)

build:
	@echo building binary for image
	CGO_ENABLED=0  GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
	#@echo building image
	#docker build -t $(NAME):$(VERSION) .
	#docker push $(NAME):$(VERSION)


build-core-linux:
	@echo building binary for core
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core

build-core:
	@echo building binary for core
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core

deploy-argocd-interlace:
	@echo deploying argocd-interlace
	kustomize build deploy | kubectl apply -f -
	#kubectl create secret docker-registry argocd-interlace-gcr-secret --docker-server="https://gcr.io"  --docker-username=_json_key  --docker-email="kgajananan2021@gmail.com"  --docker-password="`cat ~/Downloads/kg-image-registry-078a8a2d04ca.json | jq -c .`"  -n argocd-interlace
	#kubectl apply -f argo-token-secret.yaml -n argocd-interlace

delete-argocd-interlace:
	@echo deleting argocd-interlace
	kustomize build deploy | kubectl delete -f -


lint-init:
	 golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > $(TMP_DIR)lint_results_interlace.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results_interlace.txt | grep "FAIL:"))
	cat  $(TMP_DIR)lint_results_interlace.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)