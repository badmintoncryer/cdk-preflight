package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-user-pool-name", "ERROR", name,
	"Properties.UserPoolName",
	sprintf("UserPoolName '%s' is rejected by the service: word characters, spaces and + = , . @ -", [v]),
	"Rename it to satisfy word characters, spaces and + = , . @ -",
	"https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	v := resolve(name, "Properties.UserPoolName")
	is_string(v)
	not regex.match(`^[A-Za-z0-9_ \t+=,.@-]+$`, v)
}
