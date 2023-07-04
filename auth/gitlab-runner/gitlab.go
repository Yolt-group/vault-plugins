package main

import (
	"net/http"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	gitlab "github.com/xanzy/go-gitlab"
)

func getTokenID(clt *gitlab.Client, userID int, tokenName string) (int, error) {

	opts := &gitlab.GetAllImpersonationTokensOptions{
		gitlab.ListOptions{},
		gitlab.String("active"),
	}

	tokens, _, err := clt.Users.GetAllImpersonationTokens(userID, opts)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to get all impersonation tokens")
	}

	var tokenID int
	for _, token := range tokens {
		if token.Name == tokenName {
			tokenID = token.ID
			break
		}
	}

	if tokenID == 0 {
		return 0, errors.Errorf("could not find token with name %q for user %d", tokenName, userID)
	}

	return tokenID, nil
}

func createToken(clt *gitlab.Client, userID int, tokenName string) (string, int, error) {

	opts := gitlab.CreateImpersonationTokenOptions{Name: gitlab.String(tokenName),
		Scopes: &[]string{"api"},
	}

	result, _, err := clt.Users.CreateImpersonationToken(userID, &opts, nil)
	if err != nil {
		return "", 0, logical.CodedError(http.StatusForbidden, "failed to create impersonation token: "+err.Error())
	}

	return result.Token, result.ID, nil
}

func revokeToken(clt *gitlab.Client, userID, tokenID int) error {

	_, err := clt.Users.RevokeImpersonationToken(userID, tokenID)
	if err != nil {
		return errors.Wrapf(err, "failed to revoke impersonaton token (%d) for user %d", tokenID, userID)
	}

	return nil
}
