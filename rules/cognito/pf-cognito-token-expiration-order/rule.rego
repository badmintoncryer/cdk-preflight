package cdk_preflight

import rego.v1

# Cross-property inequality between differently-united durations - only
# comparable after normalizing to seconds. Unit defaults are the
# deploy-verified hours/hours/days.
_pf_cogteo_unit_secs := {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}

_pf_cogteo_unit(name, unitKey, _) := u if {
	u := resolve(name, sprintf("Properties.TokenValidityUnits.%s", [unitKey]))
	is_string(u)
}

_pf_cogteo_unit(name, unitKey, defUnit) := defUnit if {
	props := input.resources[name].properties
	is_object(props)
	tvu := object.get(props, "TokenValidityUnits", {})
	is_object(tvu)
	object.get(tvu, unitKey, "__pf_absent") == "__pf_absent"
}

_pf_cogteo_secs(name, valKey, unitKey, defUnit) := s if {
	v := to_number(resolve(name, sprintf("Properties.%s", [valKey])))
	u := _pf_cogteo_unit(name, unitKey, defUnit)
	s := v * _pf_cogteo_unit_secs[u]
}

_pf_cogteo_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html"

violation contains make_diag_full("pf-cognito-token-expiration-order", "ERROR", name,
	"Properties.AccessTokenValidity",
	sprintf("Access token validity (%v s) exceeds refresh token validity (%v s); the client create fails with \"Access and Id Token expiration times must be less than or equal to refresh token expiration times.\"", [a, r]),
	"Shorten the access token validity or lengthen the refresh token validity",
	_pf_cogteo_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	a := _pf_cogteo_secs(name, "AccessTokenValidity", "AccessToken", "hours")
	r := _pf_cogteo_secs(name, "RefreshTokenValidity", "RefreshToken", "days")
	a > r
}

violation contains make_diag_full("pf-cognito-token-expiration-order", "ERROR", name,
	"Properties.IdTokenValidity",
	sprintf("Id token validity (%v s) exceeds refresh token validity (%v s); the client create fails with \"Access and Id Token expiration times must be less than or equal to refresh token expiration times.\"", [i, r]),
	"Shorten the id token validity or lengthen the refresh token validity",
	_pf_cogteo_url) if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	i := _pf_cogteo_secs(name, "IdTokenValidity", "IdToken", "hours")
	r := _pf_cogteo_secs(name, "RefreshTokenValidity", "RefreshToken", "days")
	i > r
}
