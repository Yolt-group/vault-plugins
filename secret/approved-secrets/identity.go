package main

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) getCallerIdentity(r *logical.Request, identityTemplate string) (string, error) {
	if identityTemplate == "" {
		return b.getFistEntityAlias(r)
	} else {
		return b.applyIdentityTemplate(r, identityTemplate)
	}
}

func (b *backend) applyIdentityTemplate(r *logical.Request, tpl string) (string, error) {

	if r.EntityID == "" {
		return "", fmt.Errorf("could not get identity info cause logical.Request.EntityID is empty (do you have an identity - are you behind an auth method?)")
	}

	res, err := framework.PopulateIdentityTemplate(tpl, r.EntityID, b.System())
	if err != nil {
		return "", fmt.Errorf("could not apply identity template: %s", err)
	}

	return res, nil
}

func (b *backend) getFistEntityAlias(r *logical.Request) (string, error) {
	entity, err := b.System().EntityInfo(r.EntityID)
	if err != nil {
		return "", fmt.Errorf("could not get entity info: %s", err)
	}

	if entity == nil || len(entity.Aliases) != 1 {
		return "", fmt.Errorf("could not find entity")
	}

	alias := entity.GetAliases()[0]
	return alias.Name, nil
}
