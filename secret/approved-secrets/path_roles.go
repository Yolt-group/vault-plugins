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
	errBadMinApprovers     = logical.ErrorResponse("bad min_approvers (must be >= 1)")
	errBadSecretDataMethod = logical.ErrorResponse("bad method for secret_data (must be POST)")
)

func pathsRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Name of the role.`,
					Required:    true,
				},
				"secret_path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `The path of the requested secret.`,
					Required:    true,
				},
				"secret_path_method": &framework.FieldSchema{
					Type:          framework.TypeString,
					Default:       http.MethodGet,
					Description:   `The method of the path of the requested secret.`,
					AllowedValues: []interface{}{http.MethodGet, http.MethodPost},
				},
				"secret_data": &framework.FieldSchema{
					Type:        framework.TypeMap,
					Description: `The static input data send to the secret path (requires POST method).`,
				},
				"secret_type": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Type of secret (for example: kubernetes or ssh).`,
				},
				"secret_environment": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Environment name`,
				},
				"secret_aws_state_role": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: `Setup dedicated terraform state role while getting aws role`,
				},
				"secret_required_fields": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `Required extra fields when issuing secret.`,
				},
				"secret_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Default:     "8h",
					Description: `Default duration in seconds send to secret path.`,
				},
				"secret_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Default:     "12h",
					Description: `Max duration in seconds send to secret path.`,
				},
				"exclusive_lease": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     false,
					Description: `Ensures secret can only be requested after the TTL of last issue has expired.`,
				},
				"min_approvers": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Default:     1,
					Description: `Minimum number of approvers (>=1).`,
				},
				"bound_requester_ids": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `List of identities from template that are allowed to request. If unset, anyone may approve.`,
				},
				"bound_requester_roles": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `List of roles from Vault token's metadata that are allowed to request. If unset, any role may approve.`,
				},
				"bound_approver_ids": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `List of identities from template that are allowed to approve. If unset, anyone may approve.`,
				},
				"bound_approver_roles": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `List of roles from Vault token's metadata that are allowed to approve. If unset, any role may approve.`,
				},
				"notify_slack_channels": &framework.FieldSchema{
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
			"name":                   name,
			"secret_path":            role.SecretPath,
			"secret_path_method":     role.SecretPathMethod,
			"secret_data":            role.SecretData,
			"secret_type":            role.SecretType,
			"secret_environment":     role.SecretEnvironment,
			"secret_aws_state_role":  role.SecretAWSStateRole,
			"secret_required_fields": role.SecretRequiredFields,
			"secret_ttl":             role.SecretTTL / time.Second,
			"secret_max_ttl":         role.SecretMaxTTL / time.Second,
			"exclusive_lease":        role.ExclusiveLease,
			"bound_requester_ids":    role.BoundRequesterIDs,
			"bound_requester_roles":  role.BoundRequesterRoles,
			"bound_approver_ids":     role.BoundApproverIDs,
			"bound_approver_roles":   role.BoundApproverRoles,
			"min_approvers":          role.MinApprovers,
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
	} else if role.SecretPathMethod == "" {
		role.SecretPathMethod = d.GetDefaultOrZero("secret_path_method").(string)
	}

	// Not enforced yet with AllowedValues by framework.
	if role.SecretPathMethod != http.MethodPost && role.SecretPathMethod != http.MethodGet {
		return errBadSecretPathMethod, nil
	}

	if secretDataRaw, ok := d.GetOk("secret_data"); ok {
		role.SecretData = secretDataRaw.(map[string]interface{})
	} else {
		role.SecretData = nil
	}

	// Only allow secret data for POST method.
	if role.SecretPathMethod == http.MethodGet && role.SecretData != nil {
		return errBadSecretDataMethod, nil
	}

	if secretTypeRaw, ok := d.GetOk("secret_type"); ok {
		role.SecretType = secretTypeRaw.(string)
	}

	if SecretEnvironmentRaw, ok := d.GetOk("secret_environment"); ok {
		role.SecretEnvironment = SecretEnvironmentRaw.(string)
	}

	if SecretAWSStateRoleRaw, ok := d.GetOk("secret_aws_state_role"); ok {
		role.SecretAWSStateRole = SecretAWSStateRoleRaw.(string)
	}

	if secretRequiredFieldsRaw, ok := d.GetOk("secret_required_fields"); ok {
		role.SecretRequiredFields = secretRequiredFieldsRaw.([]string)
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

	role.ExclusiveLease = d.Get("exclusive_lease").(bool)

	if minApproversRaw, ok := d.GetOk("min_approvers"); ok {
		role.MinApprovers = minApproversRaw.(int)
	} else if role.MinApprovers == 0 {
		role.MinApprovers = d.GetDefaultOrZero("min_approvers").(int)
	}

	if role.MinApprovers < 1 {
		return errBadMinApprovers, nil
	}

	if boundRequesterIDsRaw, ok := d.GetOk("bound_requester_ids"); ok {
		role.BoundRequesterIDs = boundRequesterIDsRaw.([]string)
	}

	if boundRequesterRolesRaw, ok := d.GetOk("bound_requester_roles"); ok {
		role.BoundRequesterRoles = boundRequesterRolesRaw.([]string)
	}

	if boundApproverIDsRaw, ok := d.GetOk("bound_approver_ids"); ok {
		role.BoundApproverIDs = boundApproverIDsRaw.([]string)
	}

	if boundApproverRolesRaw, ok := d.GetOk("bound_approver_roles"); ok {
		role.BoundApproverRoles = boundApproverRolesRaw.([]string)
	}

	if notifySlackChannelsRaw, ok := d.GetOk("notify_slack_channels"); ok {
		role.NotifySlackChannels = notifySlackChannelsRaw.([]string)
	}

	return resp, b.roleAccessor.put(ctx, r.Storage, role, name)
}

type roleStorageEntry struct {
	SecretPath           string                 `json:"secret_path"`
	SecretPathMethod     string                 `json:"secret_path_method"`
	SecretData           map[string]interface{} `json:"secret_data"`
	SecretType           string                 `json:"secret_type"`
	SecretEnvironment    string                 `json:"secret_environment"`
	SecretAWSStateRole   string                 `json:"secret_aws_state_role"`
	SecretRequiredFields []string               `json:"secret_required_fields"`
	SecretTTL            time.Duration          `json:"secret_ttl"`
	SecretMaxTTL         time.Duration          `json:"secret_max_ttl"`
	ExclusiveLease       bool                   `json:"exclusive_lease"`
	MinApprovers         int                    `json:"min_approvers"`
	BoundRequesterIDs    []string               `json:"allowed_requester_ids"`
	BoundRequesterRoles  []string               `json:"allowed_requester_roles"`
	BoundApproverIDs     []string               `json:"allowed_approver_ids"`
	BoundApproverRoles   []string               `json:"allowed_approver_roles"`
	NotifySlackChannels  []string               `json:"notify_slack_channels"`
}
