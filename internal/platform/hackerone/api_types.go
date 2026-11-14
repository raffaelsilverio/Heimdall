package hackerone

import (
	"encoding/json"
	"errors"
	"strings"
)

type apiProgram struct {
	Attributes struct {
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		Policy          string `json:"policy"`
		State           string `json:"state"`
		SubmissionState string `json:"submission_state"`
		OpenScope       *bool  `json:"open_scope"`
		OffersBounties  *bool  `json:"offers_bounties"`
	} `json:"attributes"`
}

type apiStructuredScope struct {
	ID         flexibleID `json:"id"`
	Attributes struct {
		AssetType                  string `json:"asset_type"`
		AssetIdentifier            string `json:"asset_identifier"`
		EligibleForSubmission      *bool  `json:"eligible_for_submission"`
		EligibleForBounty          *bool  `json:"eligible_for_bounty"`
		Instruction                string `json:"instruction"`
		MaxSeverity                string `json:"max_severity"`
		ConfidentialityRequirement string `json:"confidentiality_requirement"`
		IntegrityRequirement       string `json:"integrity_requirement"`
		AvailabilityRequirement    string `json:"availability_requirement"`
	} `json:"attributes"`
}

type apiScopeExclusion struct {
	ID         flexibleID `json:"id"`
	Attributes struct {
		Category string `json:"category"`
		Details  string `json:"details"`
	} `json:"attributes"`
}

type flexibleID string

func (id *flexibleID) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*id = flexibleID(text)
		return nil
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return errors.New("resource id must be a string or number")
	}
	*id = flexibleID(number.String())
	return nil
}
