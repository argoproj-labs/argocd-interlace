#!/bin/bash
#
# Copyright 2020 IBM Corporation.
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
if [ $# -ne 3 ]; then
  echo "Usage: $CMDNAME <signingkey-file> <signingcert-file> <input>" 1>&2
  exit 1
fi

if [ ! -e $1 ]; then
  echo "$1 does not exist"
  exit 1
fi
if [ ! -e $2 ]; then
  echo "$2 does not exist"
  exit 1
fi
if [ ! -e $3 ]; then
  echo "$3 does not exist"
  exit 1
fi

KEY_FILE=$1
CERT_FILE=$2
INPUT_FILE=$3

# compute signature (and encoded message and certificate)

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

if [[ $YQ_VERSION == "3" ]]; then
   yq d $INPUT_FILE 'metadata.annotations."integrityshield.io/message"' -i
   yq d $INPUT_FILE 'metadata.annotations."integrityshield.io/signature"' -i
   yq d $INPUT_FILE 'metadata.annotations."integrityshield.io/certificate"' -i
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval 'del(.metadata.annotations."integrityshield.io/message")' -i $INPUT_FILE
   yq eval 'del(.metadata.annotations."integrityshield.io/signature")' -i $INPUT_FILE
   yq eval 'del(.metadata.annotations."integrityshield.io/certificate")' -i $INPUT_FILE
fi

# message
msg=`cat $INPUT_FILE | gzip -c | $base`

# signature
sig=`openssl dgst -sha256 -sign ${KEY_FILE} $INPUT_FILE | $base`

# certificate
crt=`cat ${CERT_FILE} | gzip -c | $base`

if [[ $YQ_VERSION == "3" ]]; then
   yq w -i -d* $INPUT_FILE 'metadata.annotations."integrityshield.io/message"' $msg
   yq w -i -d* $INPUT_FILE 'metadata.annotations."integrityshield.io/signature"' $sig
   yq w -i -d* $INPUT_FILE 'metadata.annotations."integrityshield.io/certificate"' $crt
elif [[ $YQ_VERSION == "4" ]]; then
   yq eval ".metadata.annotations.\"integrityshield.io/message\" = \"$msg\"" -i $INPUT_FILE
   yq eval ".metadata.annotations.\"integrityshield.io/signature\" = \"$sig\""  -i $INPUT_FILE
   yq eval ".metadata.annotations.\"integrityshield.io/certificate\" = \"$crt\""  -i $INPUT_FILE
fi