// Copyright 2022 IBM Corporation
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

package gitutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils/argoutil"
	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

func CommitAndPush(url, branch, user, email, token, commitMsg string, createOrUpdate map[string][]byte, delete []string) error {
	_, orgRepo, _, _, _ := ParseGitUrl(url)
	f := memfs.New()
	repo, err := git.Clone(memory.NewStorage(), f, &git.CloneOptions{
		URL:           "https://" + user + ":" + token + "@github.com/" + orgRepo + ".git",
		ReferenceName: plumbing.ReferenceName("refs/heads/" + branch),
	})
	if err != nil {
		// if the error is empty remote repo, ignore it
		// otherwise, return the error
		if !errors.Is(err, transport.ErrEmptyRemoteRepository) {
			return errors.Wrap(err, "failed to clone git repository")
		}
	}
	w, err := repo.Worktree()
	if err != nil {
		return errors.Wrap(err, "failed to get working tree")
	}
	toBeAdded := []string{}
	for filepath, body := range createOrUpdate {
		if fi, _ := f.Stat(filepath); fi != nil {
			err = f.Remove(filepath)
			if err != nil {
				return errors.Wrapf(err, "failed to remove the previous \"%s\"", filepath)
			}
		}

		file, err := f.OpenFile(filepath, os.O_RDWR|os.O_CREATE, 0666)
		if err != nil {
			return errors.Wrapf(err, "failed to open \"%s\" for write", filepath)
		}
		_, err = file.Write(body)
		if err != nil {
			return errors.Wrapf(err, "failed to write data to \"%s\"", filepath)
		}
		toBeAdded = append(toBeAdded, filepath)
	}

	for _, filepath := range delete {
		if fi, _ := f.Stat(filepath); fi != nil {
			err = f.Remove(filepath)
			if err != nil {
				return errors.Wrapf(err, "failed to remove \"%s\"", filepath)
			}
			toBeAdded = append(toBeAdded, filepath)
		}
	}

	for _, filepath := range toBeAdded {
		_, err = w.Add(filepath)
		if err != nil {
			return errors.Wrapf(err, "failed to add \"%s\"", filepath)
		}
	}
	hash, err := w.Commit(commitMsg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  user,
			Email: email,
			When:  time.Now(),
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to commit the changes")
	}
	err = repo.Storer.SetReference(plumbing.NewReferenceFromStrings(branch, hash.String()))
	if err != nil {
		return errors.Wrap(err, "failed to set reference for the commit")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return errors.Wrap(err, "failed to get git remote")
	}
	ref := plumbing.ReferenceName(branch)
	err = remote.Push(&git.PushOptions{
		Progress: os.Stdout,
		RefSpecs: []gitconfig.RefSpec{
			gitconfig.RefSpec(ref + ":" + plumbing.ReferenceName("refs/heads/"+branch)),
		},
	})
	if err != nil {
		return errors.Wrap(err, "failed to push the commit")
	}
	return nil
}

func GitLatestCommitSha(repoUrl, branch, gitToken string) string {
	orgName, repoName := getRepoInfo(repoUrl)

	desiredUrl := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s",
		orgName, repoName, branch)

	response, err := argoutil.QueryAPI(desiredUrl, "GET", gitToken, nil)

	if err != nil {
		log.Errorf("Error occured while query github %s ", err.Error())
		return ""
	}

	sha := gjson.Get(response, "sha")
	log.Info("Latest revision ", sha)
	return sha.String()
}

func getRepoInfo(repoUrl string) (string, string) {
	tokens := strings.Split(strings.TrimSuffix(repoUrl, "/"), "/")
	orgName := ""
	repoName := ""
	if len(tokens) == 5 {
		orgName = tokens[3]
		repoName = tokens[4]
	} else if len(tokens) == 4 {
		orgName = tokens[2]
		repoName = tokens[3]
	}

	log.Info(orgName)
	log.Info(repoName)
	return orgName, repoName
}

const gitCmd = "git"

type GitRepoResult struct {
	RootDir  string
	URL      string
	Revision string
	CommitID string
	Path     string
}
type ConfirmedDir string

func (d ConfirmedDir) HasPrefix(path ConfirmedDir) bool {
	if path.String() == string(filepath.Separator) || path == d {
		return true
	}
	return strings.HasPrefix(
		string(d),
		string(path)+string(filepath.Separator))
}

func (d ConfirmedDir) Join(path string) string {
	return filepath.Join(string(d), path)
}

func (d ConfirmedDir) String() string {
	return string(d)
}

func NewTmpConfirmedDir() (ConfirmedDir, error) {
	n, err := ioutil.TempDir("", "kustomize-")
	if err != nil {
		return "", err
	}

	// In MacOs `ioutil.TempDir` creates a directory
	// with root in the `/var` folder, which is in turn
	// a symlinked path to `/private/var`.
	// Function `filepath.EvalSymlinks`is used to
	// resolve the real absolute path.
	deLinked, err := filepath.EvalSymlinks(n)
	return ConfirmedDir(deLinked), err
}

func GetTopGitRepo(url string) (*GitRepoResult, error) {

	log.Infof("GetTopGitRepo url : %s ", url)

	r := &GitRepoResult{}
	r.URL = url

	cDir, err := NewTmpConfirmedDir()
	if err != nil {
		log.Errorf("Error in creating temporary directory: %s", err.Error())
		return nil, err
	}

	r.RootDir = cDir.String()

	_, err = utils.CmdExec(gitCmd, r.RootDir, "init")
	if err != nil {
		log.Errorf("Error in executing git init: %s", err.Error())
		return nil, err
	}
	_, err = utils.CmdExec(gitCmd, r.RootDir, "remote", "add", "origin", r.URL)
	if err != nil {
		log.Errorf("Error in executing git remote add: %s", err.Error())
		return nil, err
	}
	rev := "HEAD"

	_, err = utils.CmdExec(gitCmd, r.RootDir, "fetch", "--depth=1", "origin", rev)
	if err != nil {
		log.Errorf("Error in executing git fetch: %s", err.Error())
		return nil, err
	}
	_, err = utils.CmdExec(gitCmd, r.RootDir, "checkout", "FETCH_HEAD")
	if err != nil {
		log.Errorf("Error in executing git checkout: %s", err.Error())
		return nil, err
	}

	commitGetOut, err := utils.CmdExec(gitCmd, r.RootDir, "rev-parse", "FETCH_HEAD")
	if err != nil {
		log.Errorf("Error in executing git rev-parse: %s", err.Error())
		return nil, err
	}
	r.CommitID = strings.TrimSuffix(commitGetOut, "\n")
	return r, nil
}

const (
	refQueryRegex = "\\?(version|ref)="
	gitSuffix     = ".git"
	gitDelimiter  = "_git/"
)

func ParseGitUrl(n string) (
	host string, orgRepo string, path string, gitRef string, gitSuff string) {

	if strings.Contains(n, gitDelimiter) {
		index := strings.Index(n, gitDelimiter)
		// Adding _git/ to host
		host = normalizeGitHostSpec(n[:index+len(gitDelimiter)])
		orgRepo = strings.Split(strings.Split(n[index+len(gitDelimiter):], "/")[0], "?")[0]
		path, gitRef = peelQuery(n[index+len(gitDelimiter)+len(orgRepo):])
		return
	}
	host, n = parseHostSpec(n)
	gitSuff = gitSuffix
	if strings.Contains(n, gitSuffix) {
		index := strings.Index(n, gitSuffix)
		orgRepo = n[0:index]
		n = n[index+len(gitSuffix):]
		path, gitRef = peelQuery(n)
		return
	}

	i := strings.Index(n, "/")
	if i < 1 {
		return "", "", "", "", ""
	}
	j := strings.Index(n[i+1:], "/")
	if j >= 0 {
		j += i + 1
		orgRepo = n[:j]
		path, gitRef = peelQuery(n[j+1:])
		return
	}
	path = ""
	orgRepo, gitRef = peelQuery(n)
	return host, orgRepo, path, gitRef, gitSuff
}

func parseHostSpec(n string) (string, string) {
	var host string
	// Start accumulating the host part.
	for _, p := range []string{
		// Order matters here.
		"git::", "gh:", "ssh://", "https://", "http://",
		"git@", "github.com:", "github.com/"} {
		if len(p) < len(n) && strings.ToLower(n[:len(p)]) == p {
			n = n[len(p):]
			host += p
		}
	}
	if host == "git@" {
		i := strings.Index(n, "/")
		if i > -1 {
			host += n[:i+1]
			n = n[i+1:]
		} else {
			i = strings.Index(n, ":")
			if i > -1 {
				host += n[:i+1]
				n = n[i+1:]
			}
		}
		return host, n
	}

	// If host is a http(s) or ssh URL, grab the domain part.
	for _, p := range []string{
		"ssh://", "https://", "http://"} {
		if strings.HasSuffix(host, p) {
			i := strings.Index(n, "/")
			if i > -1 {
				host = host + n[0:i+1]
				n = n[i+1:]
			}
			break
		}
	}

	return normalizeGitHostSpec(host), n
}
func normalizeGitHostSpec(host string) string {
	s := strings.ToLower(host)
	if strings.Contains(s, "github.com") {
		if strings.Contains(s, "git@") || strings.Contains(s, "ssh:") {
			host = "git@github.com:"
		} else {
			host = "https://github.com/"
		}
	}
	if strings.HasPrefix(s, "git::") {
		host = strings.TrimPrefix(s, "git::")
	}
	return host
}

func peelQuery(arg string) (string, string) {

	r, _ := regexp.Compile(refQueryRegex)
	j := r.FindStringIndex(arg)

	if len(j) > 0 {
		return arg[:j[0]], arg[j[0]+len(r.FindString(arg)):]
	}
	return arg, ""
}
