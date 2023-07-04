package main

import (
	"context"
	"path"

	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func (b *backend) verifyCallerRoles(ctx context.Context, r *logical.Request, roles []string) error {

	cfg, err := b.config(ctx, r.Storage)
	if err != nil {
		return errors.New("could not find config: " + err.Error())
	}

	clt, err := newVaultClient(ctx, cfg.VaultAddr, cfg.VaultToken)
	if err != nil {
		return errors.New("failed to create vault client: " + err.Error())
	}

	data := map[string]interface{}{
		"accessor": r.ClientTokenAccessor,
	}

	vaultPath := "auth/token/lookup-accessor"
	secret, err := clt.Logical().Write(vaultPath, data)
	if err != nil {
		return errors.Wrapf(err, "failed to read path: %s", vaultPath)
	}
	entityID := secret.Data["entity_id"].(string)

	vaultPath = path.Join("/identity/entity/id", entityID)
	secret, err = clt.Logical().Read(vaultPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read path: %s", vaultPath)
	}

	groupIDs := secret.Data["group_ids"].([]interface{})
	found := false
	for _, id := range groupIDs {
		vaultPath = path.Join("/identity/group/id", id.(string))
		secret, err = clt.Logical().Read(vaultPath)
		if err != nil {
			return errors.Wrapf(err, "failed to read path: %s", vaultPath)
		}

		if metadataRaw, ok := secret.Data["metadata"]; ok {
			if metadata, ok := metadataRaw.(map[string]interface{}); ok {
				if primaryRoleRaw, ok := metadata["primaryRole"]; ok {
					if primaryRole, ok := primaryRoleRaw.(string); ok && strutil.StrListContains(roles, primaryRole) {
						found = true
						break
					}
				}
			}
		}
	}

	if !found {
		return errors.New("role(s) not allowed")
	}

	return nil
}
