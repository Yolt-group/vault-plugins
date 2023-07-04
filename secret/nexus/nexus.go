package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
)

type nexusClient struct {
	nexusURL, username, password string
}

func newNexusClient(nexusURL, username, password string) nexusClient {
	return nexusClient{
		nexusURL: nexusURL,
		username: username,
		password: password,
	}
}

type nexusUser struct {
	UserID       string   `json:"userId"`
	FirstName    string   `json:"firstName"`
	LastName     string   `json:"lastName"`
	EmailAddress string   `json:"emailAddress"`
	Password     string   `json:"password"`
	Status       string   `json:"status"`
	ReadOnly     bool     `json:"readOnly"`
	Roles        []string `json:"roles"`
}

func (clt nexusClient) validate() error {

	url, err := url.Parse(clt.nexusURL)
	if err != nil {
		return errors.Errorf("invalid nexus URL: %s", clt.nexusURL)
	}
	url.Path = path.Join(url.Path, "service/rest/v1/security/users")

	q := url.Query()
	q.Set("userId", clt.username)
	url.RawQuery = q.Encode()

	client := &http.Client{}
	req, err := http.NewRequest("GET", url.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clt.username, clt.password)
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to GET URL: %s", url)
	}

	if res.StatusCode != http.StatusOK {
		return errors.Errorf("unexpected result code: %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrapf(err, "failed to read response body: %s", url)
	}
	defer res.Body.Close()

	users := make([]nexusUser, 0)
	err = json.Unmarshal(body, &users)
	if err != nil {
		return errors.Errorf("failed to unmarshal response body: %s", url)
	}

	if len(users) == 0 {
		return errors.Errorf("could not find Nexus user: %s", clt.username)
	}

	nxAdminRole := "nx-admin"
	nxAdmin := false
	for _, role := range users[0].Roles {
		if role == nxAdminRole {
			nxAdmin = true
		}
	}

	if !nxAdmin {
		return errors.Errorf("missing role Nexus user %q: %s", clt.username, nxAdminRole)
	}

	return nil
}

func (clt nexusClient) createUser(userID, password string, roles []string) (*nexusUser, error) {

	url, err := url.Parse(clt.nexusURL)
	if err != nil {
		return nil, errors.Errorf("invalid nexus URL: %s", clt.nexusURL)
	}
	url.Path = path.Join(url.Path, "service/rest/v1/security/users")

	user := &nexusUser{
		UserID:       userID,
		FirstName:    userID,
		LastName:     userID,
		EmailAddress: userID + "@fake-yolt.com",
		Password:     password,
		Status:       "active",
		ReadOnly:     false,
		Roles:        roles,
	}

	data, _ := json.Marshal(user)
	client := &http.Client{}
	req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(clt.username, clt.password)
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to POST URL: %s", url)
	}

	if res.StatusCode != http.StatusOK {
		return nil, errors.Errorf("unexpected result code: %d", res.StatusCode)
	}

	return user, nil
}

func (clt nexusClient) deleteUser(userID string) error {

	url, err := url.Parse(clt.nexusURL)
	if err != nil {
		return errors.Errorf("invalid nexus URL: %s", clt.nexusURL)
	}
	url.Path = path.Join(url.Path, "service/rest/v1/security/users", userID)

	client := &http.Client{}
	req, err := http.NewRequest("DELETE", url.String(), nil)
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(clt.username, clt.password)
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to POST URL: %s", url)
	}

	if res.StatusCode != http.StatusNoContent {
		return errors.Errorf("unexpected result code: %d", res.StatusCode)
	}

	return nil
}

func (clt nexusClient) changePassword(userID, password string) error {

	url, err := url.Parse(clt.nexusURL)
	if err != nil {
		return errors.Errorf("invalid nexus URL: %s", clt.nexusURL)
	}
	url.Path = path.Join(url.Path, "service/rest/v1/security/users", userID, "change-password")

	client := &http.Client{}
	req, err := http.NewRequest("PUT", url.String(), bytes.NewBuffer([]byte(password)))
	req.SetBasicAuth(clt.username, clt.password)
	req.Header.Set("Content-Type", "text/plain")
	res, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to PUT URL: %s", url)
	}

	if res.StatusCode != http.StatusNoContent {
		return errors.Errorf("unexpected result code: %d", res.StatusCode)
	}

	return nil
}
