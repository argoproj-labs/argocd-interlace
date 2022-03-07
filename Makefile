IMG_NAME=ghcr.io/hirokuni-kitahara/argocd-interlace-controller

ARGOCD_NAMESPACE ?= argocd

<<<<<<< HEAD
USE_EXAMPLE_KEYS ?= false

=======
>>>>>>> e13053e (update installation)
VERSION=dev
TMP_DIR=/tmp/

.PHONY: build deploy undeploy check-argocd

build:
	@echo building binary for image
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o build/_bin/argocd-interlace ./cmd/core
	@echo building image
	docker build -t $(IMG_NAME):$(VERSION) .
	docker push $(IMG_NAME):$(VERSION)
	yq w -i  deploy/deployment.yaml 'spec.template.spec.containers.(name==argocd-interlace-controller).image' $(IMG_NAME):$(VERSION)

deploy: check-argocd
	@echo ---------------------------------
	@echo deploying argocd-interlace
	@echo ---------------------------------
	kustomize build deploy | kubectl apply -f -
	@echo ---------------------------------
	@echo configuring argocd-interlace
	@echo ---------------------------------
	@./scripts/setup.sh $(ARGOCD_NAMESPACE) $(USE_EXAMPLE_KEYS)
	@echo ---------------------------------
	@echo done!

undeploy:
	@echo deleting argocd-interlace
	kustomize build deploy | kubectl delete -f -

check-argocd:
	@podnum=$$(kubectl get pod -n $(ARGOCD_NAMESPACE) | grep application-controller-0 | grep Running | wc -l) && \
	if [ $$podnum -eq 1 ]; then \
		echo "ArgoCD pod is found."; \
	else \
		echo "ArgoCD pods are not running in \"$(ARGOCD_NAMESPACE)\" namespace."; \
		echo "ArgoCD is a prerequisite for argocd-interlace."; \
		exit 1; \
    fi
	

lint-init:
	 golangci-lint run --timeout 5m -D errcheck,unused,gosimple,deadcode,staticcheck,structcheck,ineffassign,varcheck > $(TMP_DIR)lint_results_interlace.txt

lint-verify:
	$(eval FAILURES=$(shell cat $(TMP_DIR)lint_results_interlace.txt | grep "FAIL:"))
	cat  $(TMP_DIR)lint_results_interlace.txt
	@$(if $(strip $(FAILURES)), echo "One or more linters failed. Failures: $(FAILURES)"; exit 1, echo "All linters are passed successfully."; exit 0)