package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	"github.com/xanzy/go-gitlab"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("issue/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Required. Name of the role.",
			},
		},
		ExistenceCheck: b.pathIssueExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathIssueReadUpdate,
			logical.UpdateOperation: b.pathIssueReadUpdate,
		},
	}
}

func (b *backend) pathIssueExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {

	name := d.Get("role").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathIssueReadUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("role").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get role")
	} else if role == nil {
		return logical.ErrorResponse("could not find role: " + name), nil
	}

	cfg, err := b.config(ctx, req.Storage, role.GitlabConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	} else if cfg == nil {
		return logical.ErrorResponse("could not find config: " + role.GitlabConfig), nil
	}

	clt, err := gitlab.NewClient(cfg.GitlabAPIToken, gitlab.WithBaseURL(cfg.GitlabAPIBaseURL))
	if err != nil {
		return nil, fmt.Errorf("gitlab client failed")
	}

	var user *gitlab.User
	if role.UserID != 0 {
		user, _, err = clt.Users.GetUser(role.UserID)
		if err != nil {
			return nil, logical.CodedError(http.StatusForbidden, "failed to get Gitlab user %d: "+err.Error())
		}
	} else {
		entity, err := b.System().EntityInfo(req.EntityID)
		if err != nil {
			return nil, logical.CodedError(http.StatusForbidden, "failed to lookup entity in Vault: "+err.Error())
		}

		if entity == nil || len(entity.Aliases) != 1 {
			return nil, logical.CodedError(http.StatusForbidden, "expected exactly one alias for entity: "+req.EntityID)
		}

		email := entity.GetAliases()[0].Name
		user, err = getUser(clt, email)
		if err != nil {
			return nil, logical.CodedError(http.StatusForbidden, fmt.Sprintf("failed to get Gitlab user %s: %s", email, err.Error()))
		}
	}

	expiresAt := time.Now().Add(24 * time.Hour) // Minimum granularity by Gitlab is 1 day.
	opts := gitlab.CreateImpersonationTokenOptions{Name: gitlab.String("Managed by Vault"),
		Scopes:    &role.Scopes,
		ExpiresAt: &expiresAt,
	}

	result, _, err := clt.Users.CreateImpersonationToken(user.ID, &opts, nil)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, "failed to create impersonation token: "+err.Error())
	}

	resp := b.Secret(secretTypeGitlabToken).Response(map[string]interface{}{
		"gitlab_token_id":     result.ID,
		"gitlab_token":        result.Token,
		"gitlab_token_scopes": fmt.Sprintf("%s", result.Scopes),
		"gitlab_user_id":      user.ID,
		"gitlab_user_email":   user.Email,
		"gitlab_username":     user.Username,
		"ttl":                 fmt.Sprintf("%s", role.TTL),
	}, map[string]interface{}{
		"gitlab_config":   role.GitlabConfig,
		"gitlab_token_id": result.ID,
		"gitlab_user_id":  user.ID,
	})

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	resp.Secret.Renewable = false

	return resp, nil
}
