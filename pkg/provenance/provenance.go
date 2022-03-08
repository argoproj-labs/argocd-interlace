//
// Copyright 2021 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package provenance

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Provenance interface {
	GenerateProvanance(target, targatDigest string, uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error
	VerifySourceMaterial() (bool, error)
	GetReference() *ProvenanceRef
}

type ProvenanceRef struct {
	UUID string
	URL  string
}

func (pr *ProvenanceRef) GetAttestation() ([]byte, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Get(pr.URL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	provEntryBytes, _ := ioutil.ReadAll(resp.Body)
	provEntryBytes = []byte(strings.TrimSuffix(string(provEntryBytes), "\n"))
	var provEntry map[string]interface{}
	err = json.Unmarshal(provEntryBytes, &provEntry)
	if err != nil {
		return nil, err
	}
	var attestationData map[string]interface{}
	for _, v := range provEntry {
		attestationData = v.(map[string]interface{})
		break
	}
	dataMap := attestationData["attestation"].(map[string]interface{})
	attestationB64DoubleEncoded := dataMap["data"].(string)
	b64Encoded, err := base64.StdEncoding.DecodeString(attestationB64DoubleEncoded)
	if err != nil {
		return nil, err
	}
	return b64Encoded, nil
}
