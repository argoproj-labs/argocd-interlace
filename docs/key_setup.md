## Key Setup

ArgoCD Interlace uses 2 key files for source repo verification and for manifest signing respectively.
These 2 keys are required in the [installation](../README.md#Installation) step.

#### For source repo verification

A GPG verification key is required for the source repo verification.
You can export your public key with `YOUR_EMAIL_OF_KEY` by the following command.

```
$ gpg --export <YOUR_EMAIL_OF_KEY> > ./pubring.gpg
```

If you do not have any GPG key or you want to use a new key, generate the new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

#### For manifest signing
A cosign signing key is required for ArgoCD Interlace to sign the generated resource manifests.

If you do not have the one, you can generate the new one by this command. Also see [the document](https://github.com/sigstore/cosign/blob/main/doc/cosign_generate-key-pair.md) in the cosign project.

```
$ cosign generate-key-pair
```

