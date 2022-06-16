### Signing source materials

ArgoCD Interlace supports source material verification. There are two files (`source-material`, `source-materials.sig`) that need to be created and placed in the same level as kustomization.yaml. 

1. Create `source-material` file which contains source material filenames and their hash values.
  ```
  $ git ls-tree -r HEAD --name-only | xargs shasum -a 256 > source-materials
  ```
  
2. Sign the summary file with `gpg` command. `<YOUR_SIGNKEY_EMAIL>` need to be the actual one.
  ```
  $ SIGNER_EMAIL=<YOUR_SIGNKEY_EMAIL> gpg --detach-sign -u "<SIGNER_EMAIL>" --armor --output - source-materials > source-materials.sig
  ```

3. Commit & push the above files to the remote repository that is used as source materials for creating an application in ArgoCD/OpenShift GitOps.
   
   
   