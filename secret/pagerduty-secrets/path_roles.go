package main

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	errBadSecretPathMethod = logical.ErrorResponse("bad secret_path_method (expected POST or GET)")
	errBadSecretDataMethod = logical.ErrorResponse("bad method for secret_data (must be POST)")
)

func pathsRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: `Name of the role.`,
					Required:    true,
				},
				"secret_path": {
					Type:        framework.TypeString,
					Description: `The path of the requested secret.`,
					Required:    true,
				},
				"secret_path_method": {
					Type:          framework.TypeString,
					Default:       http.MethodGet,
					Description:   `The method of the path of the requested secret.`,
					AllowedValues: []interface{}{http.MethodGet, http.MethodPost},
				},
				"secret_data": {
					Type:        framework.TypeMap,
					Description: `The static input data send to the secret path (requires POST method).`,
				},
				"secret_type": {
					Type:        framework.TypeString,
					Description: `Type of secret (for example: kubernetes or ssh).`,
				},
				"secret_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     "8h",
					Description: `Default duration in seconds send to secret path.`,
				},
				"secret_max_ttl": {
					Type:        framework.TypeDurationSecond,
					Default:     "12h",
					Description: `Max duration in seconds send to secret path.`,
				},
				"bound_pagerduty_schedules": {
					Type:        framework.TypeStringSlice,
					Description: `Bound pagerduty schedules the secret applies to.`,
					Required:    true,
				},
				"bound_office_hours": {
					Type:        framework.TypeBool,
					Description: `Bound to office hours (hard-coded to Europe/Amsterdam).`,
					Required:    false,
				},
				"notify_slack_channels": {
					Type:        framework.TypeStringSlice,
					Description: `Slack channels to notify.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.DeleteOperation: b.pathRoleDelete,
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
			},
		},
	}
}

func pathListRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
	}
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
	}
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roles, err := b.roleAccessor.list(ctx, req.Storage, "")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, logical.CodedError(http.StatusNotFound, "no role found")
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":                      name,
			"secret_path":               role.SecretPath,
			"secret_path_method":        role.SecretPathMethod,
			"secret_data":               role.SecretData,
			"secret_type":               role.SecretType,
			"secret_ttl":                role.SecretTTL / time.Second,
			"secret_max_ttl":            role.SecretMaxTTL / time.Second,
			"bound_pagerduty_schedules": role.BoundPagerdutySchedules,
			"bound_office_hours":        role.BoundOfficeHours,
			"notify_slack_channels":     role.NotifySlackChannels,
		},
	}

	return resp, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	if err := b.roleAccessor.delete(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, r.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		role = &roleStorageEntry{}
	}

	role.SecretPath = d.Get("secret_path").(string)

	if secretPathMethodRaw, ok := d.GetOk("secret_path_method"); ok {
		role.SecretPathMethod = secretPathMethodRaw.(string)
	}

	// Not enforced yet with AllowedValues by framework.
	if role.SecretPathMethod != http.MethodPost && role.SecretPathMethod != http.MethodGet {
		return errBadSecretPathMethod, nil
	}

	if secretDataRaw, ok := d.GetOk("secret_data"); ok {
		role.SecretData = secretDataRaw.(map[string]interface{})
	}

	// Only allow secret data for POST method.
	if role.SecretPathMethod == http.MethodGet && role.SecretData != nil {
		return errBadSecretDataMethod, nil
	}

	if secretTypeRaw, ok := d.GetOk("secret_type"); ok {
		role.SecretType = secretTypeRaw.(string)
	}

	if secretTTLRaw, ok := d.GetOk("secret_ttl"); ok {
		role.SecretTTL = time.Second * time.Duration(secretTTLRaw.(int))
	} else if r.Operation == logical.CreateOperation {
		role.SecretTTL = time.Second * time.Duration(d.Get("secret_ttl").(int))
	}

	if secretMaxTTLRaw, ok := d.GetOk("secret_max_ttl"); ok {
		role.SecretMaxTTL = time.Second * time.Duration(secretMaxTTLRaw.(int))
	} else if r.Operation == logical.CreateOperation {
		role.SecretMaxTTL = time.Second * time.Duration(d.Get("secret_max_ttl").(int))
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.SecretMaxTTL > time.Duration(0) && role.SecretTTL > role.SecretMaxTTL {
		return logical.ErrorResponse("secret_ttl should not be greater than secret_max_ttl"), nil
	}

	var resp *logical.Response
	if role.SecretMaxTTL > b.System().MaxLeaseTTL() {
		role.SecretMaxTTL = b.System().MaxLeaseTTL()
		resp = &logical.Response{}
		resp.AddWarning("secret_max_ttl is greater than the system or backend mount's maximum TTL value; secrets' max TTL value is truncated")
	}

	if boundPagerdutySchedulesRaw, ok := d.GetOk("bound_pagerduty_schedules"); ok {
		role.BoundPagerdutySchedules = boundPagerdutySchedulesRaw.([]string)
	}

	if boundOfficeHoursRaw, ok := d.GetOk("bound_office_hours"); ok {
		role.BoundOfficeHours = boundOfficeHoursRaw.(bool)
	}

	if len(role.BoundPagerdutySchedules) == 0 {
		return logical.ErrorResponse("bound_pagerduty_schedules cannot be empty"), nil
	}

	if notifySlackChannelsRaw, ok := d.GetOk("notify_slack_channels"); ok {
		role.NotifySlackChannels = notifySlackChannelsRaw.([]string)
	}

	return resp, b.roleAccessor.put(ctx, r.Storage, role, name)
}

type roleStorageEntry struct {
	SecretPath              string                 `json:"secret_path"`
	SecretPathMethod        string                 `json:"secret_path_method"`
	SecretData              map[string]interface{} `json:"secret_data"`
	SecretType              string                 `json:"secret_type"`
	SecretTTL               time.Duration          `json:"secret_ttl"`
	SecretMaxTTL            time.Duration          `json:"secret_max_ttl"`
	BoundPagerdutySchedules []string               `json:"bound_pagerduty_schedules"`
	BoundOfficeHours        bool                   `json:"bound_office_hours"`
	NotifySlackChannels     []string               `json:"notify_slack_channels"`
}
