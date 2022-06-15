## Key Setup

ArgoCD Interlace uses 2 key files for 2 features respectively.

1. GPG public key for source material verification
2. Cosign private key for signing provenance/manifest

#### 1. GPG public key for source material verification

A GPG verification key is required for the source material verification feature described [here](../README.md#additional-features).
You can export your public key with `YOUR_PUBKEY_EMAIL` by the following command.
This public key need to be corresponding to your signing key which was used for [source material signing](signing_source_material.md).

```
$ gpg --export <YOUR_PUBKEY_EMAIL> --armor > ./pubring.gpg
```

If you do not have any GPG key or you want to use a new key, generate the new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).


Then, you can configure the secret for the public key by following [this](../README.md#additional-features)

#### 2. Cosign private key for signing provenance/manifest
A cosign signing key is required for ArgoCD Interlace to sign the generated provenance and to sign the resource manifest.

If you do not have the one, you can generate the new one by this command. Also see [the document](https://github.com/sigstore/cosign/blob/main/doc/cosign_generate-key-pair.md) in the cosign project.

```
$ cosign generate-key-pair
```

Then, you can configure the secret for the private key by following [this](../README.md#additional-features)
