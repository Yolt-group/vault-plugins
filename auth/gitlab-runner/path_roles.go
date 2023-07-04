package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/go-sockaddr"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	expectedOIDCGroups        string = "expected oidc_groups"
	expectedPolicies          string = "expected policies"
	expectedProtectedPolicies string = "expected protected_policies"
)

func pathsRole(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "roles/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList(),
			},
		},
		&framework.Path{
			Pattern: "role/?$",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList(),
			},
		},
		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
					Required:    true,
				},
				"gitlab_config": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the gitlab config.",
					Required:    true,
				},
				"oidc_groups": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "Name of OIDC groups to allow.",
					Required:    true,
				},
				"policies": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "List of policies for the role on shared runners.",
					Required:    true,
				},
				"protected_policies": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "Required. List of policies for the role on protected runners.",
				},
				"num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: `Number of times issued tokens can be used`,
				},
				"ttl": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 900,
					Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fall back to the system/mount defaults.`,
				},
				"max_ttl": &framework.FieldSchema{
					Type:    framework.TypeDurationSecond,
					Default: 3600,
					Description: `Duration in seconds after which the issued token should not be allowed to
be renewed. Defaults to 0, in which case the value will fall back to the system/mount defaults.`,
				},
				"bound_runner_tokens": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "If set, only only runners with token in list are authenticated.",
				},
				"bound_cidrs": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: `If set, the remote addr and vault token is bound by cidrs.`,
				},
				"aws_bound_regions": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, defines a constraint on the EC2 instances that the region in
its identity document match one of the regions specified by this parameter.`,
				},
				"aws_bound_ami_ids": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, defines a constraint on the EC2 instances that they should be
using one of the AMI IDs specified by this parameter.`,
				},
				"aws_bound_ec2_instance_ids": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, defines a constraint on the EC2 instances to have one of the
given instance IDs. Can be a list or comma-separated string of EC2 instance IDs.`,
				},
				"aws_bound_vpc_ids": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, defines a constraint on the EC2 instance to be associated with a VPC
ID that matches one of the value specified by this parameter.`,
				},
				"aws_bound_subnet_ids": {
					Type: framework.TypeCommaStringSlice,
					Description: `If set, defines a constraint on the EC2 instance to be associated with the
subnet ID that matches one of the values specified by this parameter.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck(),
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathRoleCreateUpdate(),
				logical.UpdateOperation: b.pathRoleCreateUpdate(),
				logical.ReadOperation:   b.pathRoleRead(),
				logical.DeleteOperation: b.pathRoleDelete(),
			},
		},
	}
}

func (b *backend) pathRoleExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {

		role, err := b.role(ctx, req.Storage, d.Get("name").(string))
		if err != nil {
			return false, err
		}
		return role != nil, nil
	}
}

func (b *backend) pathRoleList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		roles, err := b.roleAccessor.list(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(roles), nil
	}
}

func (b *backend) pathRoleRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		name := d.Get("name").(string)
		role, err := b.role(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		} else if role == nil {
			return nil, logical.CodedError(http.StatusNotFound, "no role found")
		}

		// Create a map of d.to be returned
		resp := &logical.Response{
			Data: map[string]interface{}{
				"gitlab_config":              role.GitlabConfig,
				"ttl":                        role.TTL / time.Second,
				"max_ttl":                    role.MaxTTL / time.Second,
				"num_uses":                   role.NumUses,
				"oidc_groups":                role.OIDCGroups,
				"policies":                   role.Policies,
				"protected_policies":         role.ProtectedPolicies,
				"bound_runner_tokens":        role.BoundRunnerTokens,
				"bound_cidrs":                role.BoundCIDRs,
				"aws_bound_ami_ids":          role.AWSBoundAMIIDs,
				"aws_bound_ec2_instance_ids": role.AWSBoundEC2InstanceIDs,
				"aws_bound_regions":          role.AWSBoundRegions,
				"aws_bound_subnet_ids":       role.AWSBoundSubnetIDs,
				"aws_bound_vpc_ids":          role.AWSBoundVPCIDs,
			},
		}

		return resp, nil
	}
}

func (b *backend) pathRoleDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		name := d.Get("name").(string)
		if err := b.roleAccessor.delete(ctx, req.Storage, name); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func (b *backend) pathRoleCreateUpdate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		name := d.Get("name").(string)
		role, err := b.role(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}

		// Create a new entry object if this is a CreateOperation
		if role == nil && req.Operation == logical.CreateOperation {
			role = &roleStorageEntry{}
		} else if role == nil {
			return nil, fmt.Errorf("role entry not found during update operation")
		}

		if gitlabConfigRaw, ok := d.GetOk("gitlab_config"); ok {
			role.GitlabConfig = gitlabConfigRaw.(string)
		} else {
			return logical.ErrorResponse("missing gitlab_config"), nil
		}

		if oidcGroupsRaw, ok := d.GetOk("oidc_groups"); ok {
			role.OIDCGroups = oidcGroupsRaw.([]string)
		} else {
			return logical.ErrorResponse(expectedOIDCGroups), nil
		}

		if policiesRaw, ok := d.GetOk("policies"); ok {
			role.Policies = policyutil.ParsePolicies(policiesRaw)
		} else {
			return logical.ErrorResponse(expectedPolicies), nil
		}

		if protectedPoliciesRaw, ok := d.GetOk("protected_policies"); ok {
			role.ProtectedPolicies = policyutil.ParsePolicies(protectedPoliciesRaw)
		} else {
			return logical.ErrorResponse(expectedProtectedPolicies), nil
		}

		role.NumUses = d.Get("num_uses").(int)
		if role.NumUses < 0 {
			return logical.ErrorResponse("num_uses cannot be negative"), nil
		}

		if tokenTTLRaw, ok := d.GetOk("ttl"); ok {
			role.TTL = time.Second * time.Duration(tokenTTLRaw.(int))
		} else if req.Operation == logical.CreateOperation {
			role.TTL = time.Second * time.Duration(d.Get("ttl").(int))
		}

		if tokenMaxTTLRaw, ok := d.GetOk("max_ttl"); ok {
			role.MaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
		} else if req.Operation == logical.CreateOperation {
			role.MaxTTL = time.Second * time.Duration(d.Get("max_ttl").(int))
		}

		// Check that the TTL value provided is less than the MaxTTL.
		// Sanitizing the TTL and MaxTTL is not required now and can be performed
		// at credential issue time.
		if role.MaxTTL > time.Duration(0) && role.TTL > role.MaxTTL {
			return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
		}

		var resp *logical.Response
		if role.MaxTTL > b.System().MaxLeaseTTL() {
			resp = &logical.Response{}
			resp.AddWarning("max_ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
		}

		role.BoundRunnerTokens = nil
		if boundRunnerTokensRaw, ok := d.GetOk("bound_runner_tokens"); ok {
			role.BoundRunnerTokens = boundRunnerTokensRaw.([]string)
		}

		role.BoundCIDRs, err = parseutil.ParseAddrs(d.Get("bound_cidrs"))
		if err != nil {
			return logical.ErrorResponse("unable to parse bound_cidrs: " + err.Error()), nil
		}

		role.AWSBoundEC2InstanceIDs = nil
		if boundEC2InstanceIDRaw, ok := d.GetOk("aws_bound_ec2_instance_ids"); ok {
			role.AWSBoundEC2InstanceIDs = boundEC2InstanceIDRaw.([]string)
		}

		role.AWSBoundAMIIDs = nil
		if boundAMIIDsRaw, ok := d.GetOk("aws_bound_ami_ids"); ok {
			role.AWSBoundAMIIDs = boundAMIIDsRaw.([]string)
		}

		role.AWSBoundRegions = nil
		if awsBoundRegionsRaw, ok := d.GetOk("aws_bound_regions"); ok {
			role.AWSBoundRegions = awsBoundRegionsRaw.([]string)
		}

		role.AWSBoundSubnetIDs = nil
		if awsBoundSubnetIDsRaw, ok := d.GetOk("aws_bound_subnet_ids"); ok {
			role.AWSBoundSubnetIDs = awsBoundSubnetIDsRaw.([]string)
		}

		role.AWSBoundVPCIDs = nil
		if awsBoundVPCIDsRaw, ok := d.GetOk("aws_bound_vpc_ids"); ok {
			role.AWSBoundVPCIDs = awsBoundVPCIDsRaw.([]string)
		}

		if err = b.roleAccessor.put(ctx, req.Storage, role, name); err != nil {
			return nil, err
		}

		return resp, nil
	}
}

// roleStorageEntry stores all the options that are set on an role
type roleStorageEntry struct {
	GitlabConfig      string        `json:"gitlab_config"`
	OIDCGroups        []string      `json:"oidc_groups"`
	Policies          []string      `json:"policies"`
	ProtectedPolicies []string      `json:"protected_policies"`
	NumUses           int           `json:"num_uses"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	BoundRunnerTokens []string      `json:"bound_runner_tokens"`
	BoundCIDRs        []*sockaddr.SockAddrMarshaler

	AWSBoundEC2InstanceIDs []string `json:"aws_bound_ec2_instance_ids,omitempty"`
	AWSBoundAMIIDs         []string `json:"aws_bound_ami_ids,omitempty" `
	AWSBoundRegions        []string `json:"aws_bound_regions,omitempty"`
	AWSBoundSubnetIDs      []string `json:"aws_bound_subnet_ids,omitempty"`
	AWSBoundVPCIDs         []string `json:"aws_bound_vpc_ids,omitempty"`
}
