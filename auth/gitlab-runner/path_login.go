package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	"github.com/xanzy/go-gitlab"
)

var (
	errJobNotOnRunner         = errors.New("job not running on runner")
	gitlabCustomAttributeName = "groups"
)

// https://docs.gitlab.com/ee/api/runners.html#list-runner-s-jobs
func pathAuth(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:         "login/" + framework.GenericNameRegex("role"),
		HelpSynopsis:    "Authenticate using credentials",
		HelpDescription: "Authenticate using PKCS#7 signature of identity document and CI job token. The runner, project and job ID are required to get the user's corporate key.",
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"pkcs7": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "PKCS7 signature of the identity document with all \n characters removed.",
			},
			"ci_runner_id": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Gitlab CI runner ID",
			},
			"ci_project_id": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Gitlab CI project ID",
			},
			"ci_job_id": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Gitlab CI job ID",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathAuthLogin,
		},
	}
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("role").(string)
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get role")
	} else if role == nil {
		return logical.ErrorResponse("could not find role: " + roleName), nil
	}

	cfg, err := b.config(ctx, req.Storage, role.GitlabConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config")
	} else if cfg == nil {
		return logical.ErrorResponse("could not find config: " + role.GitlabConfig), nil
	}

	clt := gitlab.NewClient(nil, cfg.GitlabAPIToken)
	clt.SetBaseURL(cfg.GitlabAPIBaseURL)

	if cfg.AWSEnabled {
		if err := b.verifyEC2Instance(ctx, req, d, roleName); err != nil {
			return nil, logical.CodedError(http.StatusForbidden, err.Error())
		}
	}

	runnerID := d.Get("ci_runner_id").(int)
	projectID := d.Get("ci_project_id").(int)
	jobID := d.Get("ci_job_id").(int)
	job, err := b.getGitlabJob(ctx, req, clt, projectID, runnerID, jobID)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, err.Error())
	}

	user, _, err := clt.Users.GetUser(job.User.ID)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, err.Error())
	}

	// Not really necessary as blocked users can't trigger piplines.
	if user.State == "blocked" {
		return nil, logical.CodedError(http.StatusForbidden, "user is blocked")
	}

	groupClaims, err := getGroupClaims(clt, user)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get custom groups attribute")
	}

	if !verifyOIDCGroups(role.OIDCGroups, groupClaims) {
		return nil, errors.Errorf("failed to verify OIDC groups: %s against group claims: %s", role.OIDCGroups, groupClaims)
	}

	runner, err := getGitlabRunner(clt, runnerID)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, "Could not get Gitlab runner: "+err.Error())
	}

	maxRetries := 3
	retry := 0
	for retry < maxRetries {
		if err = b.verifyGitlabRunner(ctx, req, clt, runner, roleName, jobID); err != nil {
			switch err {
			case errJobNotOnRunner:
				retry++
				time.Sleep(time.Duration(retry) * time.Second)
			default:
				return nil, logical.CodedError(http.StatusForbidden, err.Error())
			}
		} else {
			break
		}
	}

	policies := role.Policies
	if !runner.IsShared {
		policies = role.ProtectedPolicies
	}

	var groupAliases []*logical.Alias
	for _, group := range groupClaims {
		groupAliases = append(groupAliases, &logical.Alias{
			Name: group,
		})
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Policies:    policies,
			DisplayName: user.Email,
			Metadata: map[string]string{
				"role":               roleName,
				"email":              user.Email,
				"gitlab_user_id":     fmt.Sprintf("%d", user.ID),
				"gitlab_job_id":      fmt.Sprintf("%d", jobID),
				"gitlab_pipeline_id": fmt.Sprintf("%d", job.Pipeline.ID),
			},
			Alias: &logical.Alias{
				Name: user.Email,
				Metadata: map[string]string{
					"email":              user.Email,
					"role":               roleName,
					"gitlab_user_id":     fmt.Sprintf("%d", user.ID),
					"gitlab_job_id":      fmt.Sprintf("%d", jobID),
					"gitlab_pipeline_id": fmt.Sprintf("%d", job.Pipeline.ID),
				},
			},
			GroupAliases: groupAliases,
			LeaseOptions: logical.LeaseOptions{
				TTL:       role.TTL,
				MaxTTL:    role.MaxTTL,
				Renewable: false,
			},
			BoundCIDRs: role.BoundCIDRs,
			NumUses:    role.NumUses,
		},
	}, nil
}

var (
	runners           []*gitlab.Runner
	runnersLock       sync.Mutex
	runnersLastUpdate time.Time
	runnersExpiry     = time.Hour
)

func getGitlabRunner(clt *gitlab.Client, runnerID int) (*gitlab.Runner, error) {

	runnersLock.Lock()
	defer runnersLock.Unlock()

	var err error
	if runners == nil || runnersLastUpdate.Add(runnersExpiry).After(time.Now()) {
		// This is cheaper than getting the runners details (which returns 350K of json).
		opts := &gitlab.ListRunnersOptions{Scope: gitlab.String("active")}
		runners, _, err = clt.Runners.ListAllRunners(opts, nil)
		if err != nil {
			return nil, err
		}

		runnersLastUpdate = time.Now()
	}

	var runner *gitlab.Runner
	for _, r := range runners {
		if r.ID == runnerID {
			runner = r
			break
		}
	}

	if runner == nil {
		return nil, errors.Errorf("failed to find runner with ID: %d", runner.ID)
	}

	return runner, nil
}

func (b *backend) verifyGitlabRunner(ctx context.Context,
	req *logical.Request,
	clt *gitlab.Client,
	runner *gitlab.Runner,
	roleName string,
	jobID int) error {

	if runner.Status != "online" {
		return errors.Errorf("runner not online: %d", runner.ID)
	}

	options := &gitlab.ListRunnerJobsOptions{Status: gitlab.String("running")}
	jobs, _, err := clt.Runners.ListRunnerJobs(runner.ID, options)
	if err != nil {
		return errors.Wrapf(err, "failed to get running jobs on runner: %d", runner.ID)
	}

	found := false
	for _, job := range jobs {
		if jobID == job.ID {
			found = true
			break
		}
	}

	if !found {
		return errJobNotOnRunner
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return errors.Wrapf(err, "failed to get role: %s", roleName)
	}

	if len(role.BoundRunnerTokens) > 0 {
		if !strutil.StrListContains(role.BoundRunnerTokens, runner.Token) {
			return errors.Errorf("runner with token not permitted: %s", runner.Token)
		}
	}

	return nil
}

func (b *backend) verifyEC2Instance(ctx context.Context, req *logical.Request, d *framework.FieldData, roleName string) error {

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return errors.Wrapf(err, "failed to get role: %s", roleName)
	}

	pkcs7B64 := d.Get("pkcs7").(string)
	if pkcs7B64 == "" {
		return errors.New("empty pkcs7 identity document")
	}

	idDoc, err := parseIdentityDocument(pkcs7B64)
	if err != nil {
		return errors.Wrapf(err, "failed to parse instance identity document")
	}
	if idDoc == nil {
		return errors.New("failed to verify the instance identity document using pkcs7")
	}

	if len(role.AWSBoundRegions) > 0 && !strutil.StrListContains(role.AWSBoundRegions, idDoc.Region) {
		return errors.Errorf("region %s does not satisfy the constraint on role %q", idDoc.Region, roleName)
	}

	cfg, err := b.config(ctx, req.Storage, role.GitlabConfig)
	if err != nil {
		return errors.New("could not find config")
	}

	inst, err := b.getEC2Instance(ctx, cfg, idDoc)
	if err != nil {
		return err
	}

	if *inst.State.Name != "running" {
		return errors.New("instance is not in 'running' state")
	}

	if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, role.BoundCIDRs) {
		return errors.New("remote addr not withing bound_cidrs")
	}

	if len(role.AWSBoundAMIIDs) > 0 {
		if inst.ImageId == nil {
			return errors.New("AMI ID in the instance description is nil")
		}
		if !strutil.StrListContains(role.AWSBoundAMIIDs, *inst.ImageId) {
			return errors.Errorf("AMI ID %s does not belong to role %q", *inst.ImageId, roleName)
		}
	}

	if len(role.AWSBoundSubnetIDs) > 0 {
		if inst.SubnetId == nil {
			return errors.New("subnet ID in the instance description is nil")
		}
		if !strutil.StrListContains(role.AWSBoundSubnetIDs, *inst.SubnetId) {
			return errors.Errorf("subnet ID %s does not satisfy the constraint on role %q", *inst.SubnetId, roleName)
		}
	}

	if len(role.AWSBoundVPCIDs) > 0 {
		if inst.VpcId == nil {
			return errors.New("VPC ID in the instance description is nil")
		}
		if !strutil.StrListContains(role.AWSBoundVPCIDs, *inst.VpcId) {
			return errors.Errorf("VPC ID %s does not satisfy the constraint on role %q", *inst.VpcId, roleName)
		}
	}

	if len(role.AWSBoundEC2InstanceIDs) > 0 && !strutil.StrListContains(role.AWSBoundEC2InstanceIDs, *inst.InstanceId) {
		return errors.Errorf("instance ID %s is not whitelisted for role %q", *inst.InstanceId, roleName)
	}

	return nil
}

func (b *backend) getGitlabJob(ctx context.Context, req *logical.Request, clt *gitlab.Client, projectID, runnerID, jobID int) (*gitlab.Job, error) {
	job, _, err := clt.Jobs.GetJob(projectID, jobID)
	if err != nil {
		return nil, err
	}

	if runnerID != job.Runner.ID {
		return nil, errors.New("runner ID does not match job's runner ID")
	}

	if gitlab.BuildStateValue(job.Status) != gitlab.Running {
		return nil, errors.Errorf("job %d not running", jobID)
	}

	return job, nil
}

func (b *backend) getGitlabUser(ctx context.Context, req *logical.Request, clt *gitlab.Client, projectID, runnerID, jobID int) (*gitlab.User, error) {

	job, _, err := clt.Jobs.GetJob(projectID, jobID)
	if err != nil {
		return nil, err
	}

	if runnerID != job.Runner.ID {
		return nil, errors.New("runner ID does not match job's runner ID")
	}

	if gitlab.BuildStateValue(job.Status) != gitlab.Running {
		return nil, errors.Errorf("job %d not running", jobID)
	}

	user, _, err := clt.Users.GetUser(job.User.ID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func getGroupClaims(clt *gitlab.Client, user *gitlab.User) ([]string, error) {

	groupsAttrRaw, _, err := clt.CustomAttribute.GetCustomUserAttribute(user.ID, gitlabCustomAttributeName)
	if err != nil {
		return nil, errors.Errorf("fetching gitlab custom attribute for %s failed", user.Email)
	}

	return strings.Split(strings.Trim(groupsAttrRaw.Value, "[]"), " "), nil
}

func verifyOIDCGroups(oidcGroups, groupClaims []string) bool {

	for _, group := range oidcGroups {
		for _, claim := range groupClaims {
			if group == claim {
				return true
			}
		}
	}

	return false
}
