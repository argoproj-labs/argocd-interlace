#!/bin/bash

set -e

sourcerepo=$1
opt=$2

if [ ! -d $sourcerepo ]; then
    echo "the source repo \"$sourcerepo\" does not exist."
    exit 1
fi

cd $sourcerepo

git ls-tree -r HEAD --name-only | grep -v source-materials | xargs sha256sum > source-materials

gpg --detach-sign --armor --output source-materials.sig source-materials

git status

if [[ $opt == "--push" ]]; then
    git add source-materials source-materials.sig
    git commit -s -m "sign source repository contents"
    git push
else
    echo "------------------------------------------------------------------------"
    echo "Do the following commands to upload signatures to the remote repository."
    echo "    $ cd $sourcerepo"
    echo "    $ git add source-materials source-materials.sig"
    echo "    $ git commit -s -m \"sign source repository contents\""
    echo "    $ git push"
fi