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

package verify

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	// package golang.org/x/crypto/openpgp is deprecated: this package is unmaintained except for security fixes.
	// New applications should consider a more focused, modern alternative to OpenPGP for their specific task.
	// If you are required to interoperate with OpenPGP systems and need a maintained package, consider a community fork.
	// See https://golang.org/issue/44226.
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func VerifySignature(keyPath string, msg, sig *os.File) (bool, string, *Signer, []byte, error) {

	if keyRing, err := LoadPublicKey(keyPath); err != nil {
		return false, "Error when loading key ring", nil, nil, err
	} else if signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msg, sig, nil); signer == nil {
		if err != nil {
			log.Error("Signature verification error:", err.Error())
		}
		return false, "Signed by unauthrized subject (signer is not in public key), or invalid format signature", nil, nil, nil
	} else {
		idt := GetFirstIdentity(signer)
		fingerprint := ""
		if signer.PrimaryKey != nil {
			fingerprint = fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
		}
		return true, "", NewSignerFromUserId(idt.UserId), []byte(fingerprint), nil
	}
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}

type Signer struct {
	Email              string `json:"email,omitempty"`
	Name               string `json:"name,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	Fingerprint        []byte `json:"finerprint"`
}

func NewSignerFromUserId(uid *packet.UserId) *Signer {
	return &Signer{
		Email:   uid.Email,
		Name:    uid.Name,
		Comment: uid.Comment,
	}
}

func LoadPublicKey(keyPath string) (openpgp.EntityList, error) {
	var keyRingReader io.Reader
	var err error

	keyRingReader, err = os.Open(filepath.Clean(keyPath))
	if err != nil {
		return nil, errors.Wrap(err, "failed to read public key stream")
	}

	entities := []*openpgp.Entity{}
	var tmpList openpgp.EntityList
	var err1, err2 error
	// try loading it as a non-armored public key
	tmpList, err1 = openpgp.ReadKeyRing(keyRingReader)
	if err1 != nil {
		// keyRingReader is a stream, so it must be re-loaded after first trial
		keyRingReader, _ = os.Open(filepath.Clean(keyPath))
		// try loading it as an armored public key
		tmpList, err2 = openpgp.ReadArmoredKeyRing(keyRingReader)
	}
	// if both trial failed, return error
	if err1 != nil && err2 != nil {
		err = fmt.Errorf("failed to load public key; %s; %s", err1.Error(), err2.Error())
	} else if len(tmpList) > 0 {
		for _, tmp := range tmpList {
			entities = append(entities, tmp)
		}
	}
	return openpgp.EntityList(entities), err
}

func CompareHash(sourceMaterialPath string, baseDir string) (bool, error) {
	sourceMaterial, err := ioutil.ReadFile(sourceMaterialPath)

	if err != nil {
		log.Errorf("Error in reading sourceMaterialPath:  %s", err.Error())
		return false, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(sourceMaterial)))

	for scanner.Scan() {
		l := scanner.Text()

		data := strings.Split(l, " ")
		if len(data) > 2 {
			hash := data[0]
			path := data[2]

			absPath := filepath.Join(baseDir, "/", path)
			computedFileHash, err := utils.ComputeHash(absPath)
			log.Info("file: ", path, " hash:", hash, " absPath:", absPath, " computedFileHash: ", computedFileHash)
			if err != nil {
				return false, err
			}

			if hash != computedFileHash {
				return false, nil
			}
		} else {
			continue
		}
	}
	return true, nil
}
