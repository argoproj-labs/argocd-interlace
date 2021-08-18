package sign

import (
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
)

func SignManifest(imageRef, keyPath, manifestPath, signedManifestPath string) error {

	so := &k8smanifest.SignOption{
		ImageRef:         imageRef,
		KeyPath:          keyPath,
		Output:           signedManifestPath,
		UpdateAnnotation: true,
		ImageAnnotations: nil,
	}

	_, err := k8smanifest.Sign(manifestPath, so)
	if err != nil {
		return err
	}
	return nil
}
