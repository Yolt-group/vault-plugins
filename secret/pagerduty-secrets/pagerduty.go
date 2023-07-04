package main

import (
	"strings"
	"time"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/pkg/errors"
)

func getScheduleID(client *pagerduty.Client, name string) (string, error) {

	var opts = pagerduty.ListSchedulesOptions{Query: name}
	res, err := client.ListSchedules(opts)
	if err != nil {
		return "", errors.Wrap(err, "failed to get pagerduty schedules")
	}

	var id string
	for _, s := range res.Schedules {
		if s.Name == name {
			id = s.ID
			break
		}
	}

	if id == "" {
		return "", errors.Errorf("pagerduty schedule not found: %s", name)
	}

	return id, nil
}

func getScheduledUsersEmail(client *pagerduty.Client, scheduleID string) ([]string, error) {

	now := time.Now().Format(time.RFC3339)
	res, err := client.GetSchedule(scheduleID, pagerduty.GetScheduleOptions{Since: now, Until: now})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get pagerduty schedule")
	}

	emails := make([]string, 0, len(res.FinalSchedule.RenderedScheduleEntries))
	for _, e := range res.FinalSchedule.RenderedScheduleEntries {

		res, err := client.GetUser(e.User.ID, pagerduty.GetUserOptions{})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get user: %s", e.User.ID)
		}

		emails = append(emails, res.Email)
	}

	return emails, nil
}

func verifyBoundPagerdutySchedules(pagerdutyAPIEndpoint, pagerdutyAPIToken, issuerEmail string, schedules []string) (string, error) {

	var schedule string
	pdClient := pagerduty.NewClient(pagerdutyAPIToken, pagerduty.WithAPIEndpoint(pagerdutyAPIEndpoint))
	for _, s := range schedules {

		id, err := getScheduleID(pdClient, s)
		if err != nil {
			return "", errors.Errorf("could not find schedule %q: %s", s, err)
		}

		emails, err := getScheduledUsersEmail(pdClient, id)
		if err != nil {
			return "", err
		}

		emails = strutil.RemoveDuplicates(emails, true) // Also trims and converts to lowercase
		if strutil.StrListContains(emails, strings.ToLower(issuerEmail)) {
			schedule = s
			break
		}
	}

	return schedule, nil
}
