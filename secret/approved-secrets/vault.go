package main

import (
	"context"
	"fmt"
	"path"
	"strings"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/pkg/errors"
)

func newVaultClient(ctx context.Context, vaultAddr, vaultToken string) (*api.Client, error) {

	vaultcfg := api.DefaultConfig()
	if vaultcfg == nil {
		return nil, errors.New("failed to create default Vault client config")
	}
	if vaultcfg.Error != nil {
		return nil, errors.Wrapf(vaultcfg.Error, "failed to create default Vault client config")
	}

	vaultcfg.Address = vaultAddr
	clt, err := api.NewClient(vaultcfg)
	if err != nil {
		errors.Wrapf(err, "failed to create Vault client")
	}

	clt.SetToken(vaultToken)

	return clt, nil
}

func createClientToken(clt *api.Client,
	tokenData map[string]interface{},
	entityAlias string) (*api.Secret, error) {

	var policies []string
	if policiesRaw, ok := tokenData["policies"]; ok {
		policies, _ = parseutil.ParseCommaStringSlice(policiesRaw)
	} else {
		return nil, errors.Errorf("expected 'policies' in secret data, got: %s", tokenData)
	}

	entityAlias = strings.ToLower(entityAlias)
	data := map[string]interface{}{
		"allowed_policies":       policies,
		"allowed_entity_aliases": entityAlias,
		"orphan":                 true,
		"renewable":              false,
	}

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create uuid")
	}

	role := fmt.Sprintf("pagerduty-secrets-%s", uuid)
	vaultPath := path.Join("/auth/token/roles", role)
	secret, err := clt.Logical().Write(vaultPath, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create one-time token policy")
	}

	defer func(path string) {
		clt.Logical().Delete(path)
	}(vaultPath)

	vaultPath = path.Join("/auth/token/create", role)
	tokenData["display_name"] = entityAlias
	tokenData["entity_alias"] = entityAlias

	secret, err = clt.Logical().Write(vaultPath, tokenData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create Vault token for issuing secret for: %s", entityAlias)
	}

	return secret, nil
}
