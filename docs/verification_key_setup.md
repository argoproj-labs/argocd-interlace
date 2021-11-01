## Setting up Verification Key

## Signing and Verification Key Setup
ArgoCD Interlace requires a key pair (signing and verification keys) for verifying integrity of source materials used for generating manifest. ArgoCD Interlace PGP key for signing source materials. A secret resource (keyring-secret) which contains public key should be setup in a cluster for enabling signature verification by ArgoCD Interlace. 

This document uses [gpg key](https://www.gnupg.org/index.html) for setting up signing and verification key.

The following steps show how to setup a GPG key and how you can export your pubkey to a file.


### GPG Key Setup

First, you need to setup GPG key.

If you do not have any PGP key or you want to use new key, generate new one and export it to a file. See [this GitHub document](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/generating-a-new-gpg-key).

The following example shows how to generate GNUPG key (with your email address e.g. signer@enterprise.com)

```
    gpg --full-generate-key

```

Confirm if key is avaialble in keyring

```
    gpg -k signer@enterprise.com
    gpg: checking the trustdb
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
    pub   rsa2048 2020-01-27 [SC]
          9D96363D64B579F077AD9446D57583E19B793A64
    uid           [ultimate] Signer <signer@enterprise.com>
    sub   rsa2048 2020-01-27 [E]

```

Then, you need to export a public key to a file. The following example shows a pubkey for a signer identified by an email `signer@enterprise.com` is exported and stored in `/tmp/pubring.gpg`. (Use the filename `pubring.gpg`.)

```
$ gpg --export signer@enterprise.com > /tmp/pubring.gpg
```

When deploying ArgoCD Interlace `/tmp/pubring.gpg` would be used for setting up verification key as secret resource with the name `keyring-secret`
