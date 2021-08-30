#!/bin/bash
#
# Copyright 2021 IBM Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMDNAME=`basename $0`
if [ $# -ne 2 ]; then
  echo "Usage: $CMDNAME <signer-email> <input-file>" 1>&2
  exit 1
fi

if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi

if ! [ -x "$(command -v yq)" ]; then
   echo 'Error: yq is not installed.' >&2
   exit 1
fi

SIGNER=$1
INPUT_FILE=$2

if [ -z "$SIGNER" ]; then
   echo "signer-email is empty. please provide it."
   exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
   echo "Input file does not exist. please create it."
   exit 1
fi

if [ -z "$TMP_DIR" ]; then
    echo "TMP_DIR is empty. Setting /tmp as default"
    TMP_DIR="/tmp"
fi

if [ ! -d $TMP_DIR ]; then
    echo "$TMP_DIR directory does not exist, please create it."
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    base='base64 -w 0'
elif [[ "$OSTYPE" == "darwin"* ]]; then
    base='base64'
fi

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )
if ! { [ $YQ_VERSION == "3" ] || [ $YQ_VERSION == "4" ]; } then
   echo Please choose yq version: 3.x.x or 4.x.x !
   exit 1
fi

# remove last occurance of '---'
# sed -i '$ s/---//g' $INPUT_FILE

if [[ $YQ_VERSION == "3" ]]; then
   yq d $INPUT_FILE 'metadata.annotations."integrityshield.io/message"' -i
   yq d $INPUT_FILE 'metadata.annotations."integrityshield.io/signature"' -i
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval 'del(.metadata.annotations."integrityshield.io/message")' -i $INPUT_FILE
   yq eval 'del(.metadata.annotations."integrityshield.io/signature")' -i $INPUT_FILE
fi

# message
msg=`cat $INPUT_FILE | gzip -c | $base`

# signature
sig=`cat $INPUT_FILE > $TMP_DIR/temp-aaa.yaml; gpg -u $SIGNER --detach-sign --armor --output - $TMP_DIR/temp-aaa.yaml | $base`

if [[ $YQ_VERSION == "3" ]]; then
   yq w -i -d* $INPUT_FILE 'metadata.annotations."integrityshield.io/message"' $msg
   yq w -i -d* $INPUT_FILE 'metadata.annotations."integrityshield.io/signature"' $sig
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval ".metadata.annotations.\"integrityshield.io/message\" = \"$msg\"" -i $INPUT_FILE
   yq eval ".metadata.annotations.\"integrityshield.io/signature\" = \"$sig\""  -i $INPUT_FILE
fi

if [ -f $TMP_DIR/temp-aaa.yaml ]; then
   rm $TMP_DIR/temp-aaa.yaml
fi