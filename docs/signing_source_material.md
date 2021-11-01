### Signing source materials

1. Create `source-material` file which contains source material filenames and their hash values.
  ```
  $ git ls-tree -r HEAD --name-only | xargs shasum -a 256 > source-materials
  ```
  
2. Sign the summary file with `gpg` command.
  ```
  $ gpg --detach-sign -u "signer@enterprise.com" --armor --output - source-materials > source-materials.sig
  ```

3. Commit & push the above files to the remote repository that is used as source creating application in ArgoCD/OpenShift GitOps.
   See exmaple [here](https://github.com/gajananan/kustomize/tree/master/examples/helloWorld)
   
   