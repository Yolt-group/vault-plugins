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

const (
	expectedEmail string = "expected email"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("issue/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `Required. Name of the role.`,
			},
			"email": {
				Type:        framework.TypeString,
				Description: `Required. Email of Gitlab user.`,
			},
			"ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire.`,
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
		return logical.ErrorResponse(fmt.Sprintf("role %q does not exists", name)), nil
	}

	cfg, err := b.config(ctx, req.Storage, role.GitlabConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	} else if cfg == nil {
		return logical.ErrorResponse("could not find config: " + role.GitlabConfig), nil
	}

	var ttl time.Duration
	if ttlRaw, ok := d.GetOk("ttl"); ok {
		ttl = time.Second * time.Duration(ttlRaw.(int))
	} else {
		ttl = role.TTL
	}

	warnings := make([]string, 0)
	if ttl > role.MaxTTL {
		ttl = role.MaxTTL
		warnings = append(warnings, "max_ttl is greater than the role's maximum TTL value; issued TTL value will be truncated")
	}

	var email string
	if rawEmail, ok := d.GetOk("email"); ok {
		email = rawEmail.(string)
	} else {
		return logical.ErrorResponse(expectedEmail), nil
	}

	clt := gitlab.NewClient(nil, cfg.GitlabAPIToken)
	clt.SetBaseURL(cfg.GitlabAPIBaseURL)

	user, err := getUser(clt, email)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, "failed to get user: "+err.Error())
	}

	opts := &gitlab.ModifyUserOptions{Admin: gitlab.Bool(true)}
	_, _, err = clt.Users.ModifyUser(user.ID, opts)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, "failed to modify Gitlab user: "+err.Error())
	}

	resp := b.Secret(secretTypeGitlabAdmin).Response(map[string]interface{}{
		"user_id": user.ID,
		"ttl":     fmt.Sprintf("%s", ttl),
	}, map[string]interface{}{
		"gitlab_config": role.GitlabConfig,
		"user_id":       user.ID,
	})

	for _, w := range warnings {
		resp.AddWarning(w)
	}

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = ttl
	resp.Secret.Renewable = false

	return resp, nil
}
