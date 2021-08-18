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
  echo "Usage: $CMDNAME <signed-manifest> <name> <output-file>" 1>&2
  exit 1
fi


SIGNED_MANIFEST=$1
NAME=$2
OUTPUT_FILE=$3

if [ -f $OUTPUT_FILE ]; then
   rm $OUTPUT_FILE
fi

base_cm='{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":""},"data": {} }'

YQ_VERSION=$(yq --version 2>&1 | awk '{print $3}' | cut -c 1 )

#echo $YQ_VERSION
#echo $base_cm

if [[ $YQ_VERSION == "3" ]]; then
  echo -e $base_cm | yq r - --prettyPrint >> "$OUTPUT_FILE"
elif [[ $YQ_VERSION == "4" ]]; then
  echo -e $base_cm | yq eval --prettyPrint >> "$OUTPUT_FILE"
fi

echo "Before"
cat "$OUTPUT_FILE"
echo "----------------"
if [[ $YQ_VERSION == "3" ]]; then

    message=$(cat $SIGNED_MANIFEST| yq r - 'metadata.annotations."cosign.sigstore.dev/message"')
    signature=$(cat $SIGNED_MANIFEST| yq r - 'metadata.annotations."cosign.sigstore.dev/signature"')

    yq w -i $OUTPUT_FILE metadata.name "$NAME"  
    yq w -i $OUTPUT_FILE data.signature "$signature"
    yq w -i $OUTPUT_FILE data.message "$message"
fi

if [ -f $OUTPUT_FILE ]; then
  cat "$OUTPUT_FILE"
else
  echo "Failed to generate output file"
fi


