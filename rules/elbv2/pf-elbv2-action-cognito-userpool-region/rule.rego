package cdk_preflight

import rego.v1

_pf_elbacur_fix := "Point at a user pool in the region this stack deploys to"

_pf_elbacur_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AuthenticateCognitoActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-cognito-userpool-region", "ERROR", name,
	sprintf("Properties.%s.%d.AuthenticateCognitoConfig.UserPoolArn", [a.prop, a.index]),
	sprintf("The user pool is in %s but this stack deploys to %s; a listener can only authenticate against a user pool in its own region", [r, _pf_elb_region]),
	_pf_elbacur_fix, _pf_elbacur_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	cc := _pf_elb_oget(a.value, "AuthenticateCognitoConfig")
	arn := _pf_elb_oget(cc, "UserPoolArn")
	r := _pf_elb_arn_region(arn)
	r != _pf_elb_region
}
