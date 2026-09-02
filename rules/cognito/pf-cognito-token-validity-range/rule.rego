package cdk_preflight

import rego.v1

# The schema types the validities as bare integers; the real ranges are
# per token type AND unit (access/id: 5 minutes-1 day, refresh: 60
# minutes-10 years). Unit defaults (hours/hours/days) are deploy-verified.
_pf_cogtvr_unit_secs := {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}

_pf_cogtvr_unit(name, unitKey, _) := u if {
	u := resolve(name, sprintf("Properties.TokenValidityUnits.%s", [unitKey]))
	is_string(u)
}

_pf_cogtvr_unit(name, unitKey, defUnit) := defUnit if {
	props := input.resources[name].properties
	is_object(props)
	tvu := object.get(props, "TokenValidityUnits", {})
	is_object(tvu)
	object.get(tvu, unitKey, "__pf_absent") == "__pf_absent"
}

_pf_cogtvr_secs(name, valKey, unitKey, defUnit) := s if {
	v := to_number(resolve(name, sprintf("Properties.%s", [valKey])))
	u := _pf_cogtvr_unit(name, unitKey, defUnit)
	s := v * _pf_cogtvr_unit_secs[u]
}

_pf_cogtvr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html"

_pf_cogtvr_ai_bad(s) if s < 300

_pf_cogtvr_ai_bad(s) if s > 86400

_pf_cogtvr_rt_bad(s) if s < 3600

_pf_cogtvr_rt_bad(s) if s > 315360000

violation contains make_diag_full("pf-cognito-token-validity-range", "ERROR", name,
	"Properties.AccessTokenValidity",
	sprintf("AccessTokenValidity works out to %v seconds, outside 5 minutes-1 day; the client create fails with \"Invalid range for token validity.\"", [s]),
	"Keep the access token validity between 5 minutes and 1 day",
	_pf_cogtvr_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	s := _pf_cogtvr_secs(name, "AccessTokenValidity", "AccessToken", "hours")
	_pf_cogtvr_ai_bad(s)
}

violation contains make_diag_full("pf-cognito-token-validity-range", "ERROR", name,
	"Properties.IdTokenValidity",
	sprintf("IdTokenValidity works out to %v seconds, outside 5 minutes-1 day; the client create fails with \"Invalid range for token validity.\"", [s]),
	"Keep the id token validity between 5 minutes and 1 day",
	_pf_cogtvr_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	s := _pf_cogtvr_secs(name, "IdTokenValidity", "IdToken", "hours")
	_pf_cogtvr_ai_bad(s)
}

violation contains make_diag_full("pf-cognito-token-validity-range", "ERROR", name,
	"Properties.RefreshTokenValidity",
	sprintf("RefreshTokenValidity works out to %v seconds, outside 60 minutes-10 years; the client create fails with \"Invalid range for token validity.\"", [s]),
	"Keep the refresh token validity between 60 minutes and 10 years",
	_pf_cogtvr_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	s := _pf_cogtvr_secs(name, "RefreshTokenValidity", "RefreshToken", "days")
	_pf_cogtvr_rt_bad(s)
}
