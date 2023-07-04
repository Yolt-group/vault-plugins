package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ashwanthkumar/slack-go-webhook"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of role of approved request.",
				Required:    true,
			},
			"reason": {
				Type:        framework.TypeString,
				Description: "Reason for requesting secret.",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathIssueCreateUpdate,
			logical.UpdateOperation: b.pathIssueCreateUpdate,
		},
	}
}

func (b *backend) pathIssueCreateUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("name").(string)
	role, err := b.role(ctx, r.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q does not exists", roleName)), nil
	}

	reason := d.Get("reason").(string)
	if reason == "" {
		return logical.ErrorResponse("field 'reason' is mandatory"), nil
	}

	cfg, err := b.config(ctx, r.Storage)
	if err != nil {
		return logical.ErrorResponse("could not find config: " + err.Error()), nil
	}

	issuerID, err := b.getCallerIdentity(r, cfg.IdentityTemplate)
	if err != nil {
		return logical.ErrorResponse("failed to get caller's identity: " + err.Error()), nil
	}

	err = verifyBoundOfficeHours(role.BoundOfficeHours)
	if err != nil {
		return logical.ErrorResponse("failed to verify bound_office_hours: " + err.Error()), nil
	}

	schedule, err := verifyBoundPagerdutySchedules(cfg.PagerdutyAPIEndpoint, cfg.PagerdutyAPIToken, issuerID, role.BoundPagerdutySchedules)
	if err != nil {
		return logical.ErrorResponse("failed to verify bound_pagerduty_schedules: " + err.Error()), nil
	} else if schedule == "" {
		return logical.ErrorResponse(fmt.Sprintf("%s not scheduled for any schedule: %s", strings.ToLower(issuerID), role.BoundPagerdutySchedules)), nil
	}

	clt, err := newVaultClient(ctx, cfg.VaultAddr, cfg.VaultToken)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create vault client: %s", err)), nil
	}

	tokenData := map[string]interface{}{"policies": cfg.VaultPolicies}
	secret, err := createClientToken(clt, tokenData, issuerID)
	if err != nil {
		return logical.ErrorResponse("could not create Vault client token: " + err.Error()), nil
	}

	clt.SetToken(secret.Auth.ClientToken)

	var ttl time.Duration
	if rawTTL, ok := d.GetOk("ttl"); ok {
		ttl = time.Second * time.Duration(rawTTL.(int))
	} else {
		ttl = role.SecretTTL
	}

	var ttlWarning string
	if ttl > role.SecretMaxTTL {
		ttlWarning = fmt.Sprintf("Specified ttl is greater than role-secret's max TTL, capped to max TTL: %s", role.SecretMaxTTL)
		ttl = role.SecretMaxTTL
	}

	secretData := make(map[string]interface{})
	if strings.ToUpper(role.SecretPathMethod) == http.MethodPost {
		secretData["ttl"] = ttl / time.Second
		for k, v := range b.applyIdentityTemplateToSecretData(r, role.SecretData) {
			secretData[k] = v
		}

		if role.SecretType == "vault-token" {
			secret, err = createClientToken(clt, secretData, issuerID)
		} else {
			secret, err = clt.Logical().Write(role.SecretPath, secretData)
		}
	} else {
		secret, err = clt.Logical().Read(role.SecretPath)
	}
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to %s secret %q: %s", role.SecretPathMethod, role.SecretPath, err)), nil
	}

	attach := slack.Attachment{}
	attach.AddField(slack.Field{Value: fmt.Sprintf("*Reason:* %s", reason)})

	payload := slack.Payload{
		Text:        fmt.Sprintf("%s requests role *%q*", issuerID, roleName),
		Username:    "Vault Pagerduty Plugin",
		Attachments: []slack.Attachment{attach},
	}

	for _, c := range role.NotifySlackChannels {
		payload.Channel = c
		errs := slack.Send(cfg.SlackWebhookURL, "", payload)
		if len(errs) > 0 {
			return logical.ErrorResponse(fmt.Sprintf("failed to send Slack notification to channel %q: %s", c, errs[0])), nil
		}
	}

	data := secret.Data
	if role.SecretType == "vault-token" { // Got a vault token
		bytes, _ := json.Marshal(*secret.Auth)
		data = map[string]interface{}{}
		json.Unmarshal(bytes, &data)
	}

	return &logical.Response{Data: data, Warnings: []string{ttlWarning}}, nil
}

func (b *backend) applyIdentityTemplateToSecretData(r *logical.Request, secretData map[string]interface{}) map[string]interface{} {

	data := map[string]interface{}{}
	for k, v := range secretData {

		switch casted := v.(type) {
		case string:
			data[k] = v
			matched, _ := regexp.MatchString(`^{{.+?}}$`, casted)
			if matched && r.EntityID != "" {
				res, err := framework.PopulateIdentityTemplate(casted, r.EntityID, b.System())
				if err != nil {
					continue
				}
				data[k] = res
			}
		case map[string]interface{}:
			data[k] = b.applyIdentityTemplateToSecretData(r, casted)
		default:
			data[k] = v
		}
	}

	return data
}

func verifyBoundOfficeHours(verify bool) error {

	if !verify {
		return nil
	}

	locstr := "Europe/Amsterdam"
	loc, err := time.LoadLocation(locstr)
	if err != nil {
		return errors.Wrap(err, "failed to read location")
	}

	now := time.Now().In(loc)
	if now.Weekday() == time.Saturday ||
		now.Weekday() == time.Sunday ||
		now.Hour() < 8 ||
		now.Hour() > 17 {
		return errors.New("not within office hours Mon-Fri 09:00-18 Europe/Amsterdam")
	}

	return nil
}
