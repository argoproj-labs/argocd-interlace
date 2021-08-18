
#!/bin/bash

LOG_INDEX=$1

UUID=$(curl -s "https://rekor.sigstore.dev/api/v1/log/entries/?logIndex=${LOG_INDEX}" | jq keys | jq -c '.[]')

if [ -z "$UUID" ]; then
    echo "Please wait few secs before querying sigstore log"
    exit 0
fi

echo $UUID
QUERY=".${UUID}.attestation.data"
echo $QUERY
sleep 2
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/?logIndex=${LOG_INDEX}" | jq -r $QUERY | base64 -D | base64 -D | jq .





