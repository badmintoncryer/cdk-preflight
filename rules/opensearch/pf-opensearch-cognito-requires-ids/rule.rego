package cdk_preflight

import rego.v1

_pf_oscid_gaps(name) := {k |
	some k, _v in {"RoleArn": 1, "UserPoolId": 1, "IdentityPoolId": 1}
	_pf_os_missing(name, "CognitoOptions", k)
}

violation contains make_diag_full("pf-opensearch-cognito-requires-ids", "ERROR", name,
	"Properties.CognitoOptions",
	sprintf("CognitoOptions is enabled but %v missing; CreateDomain stops at the first gap (\"RoleArn needs to be specified\")", [concat(", ", sort(gaps))]),
	"Set RoleArn, UserPoolId and IdentityPoolId, or turn CognitoOptions off",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-cognitooptions.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "CognitoOptions", "Enabled")
	gaps := _pf_oscid_gaps(name)
	gaps != set()
}
