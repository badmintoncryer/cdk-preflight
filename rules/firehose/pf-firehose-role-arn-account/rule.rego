package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-role-arn-account", "ERROR", name,
	sprintf("%s.RoleARN", [path]),
	sprintf("the delivery role lives in account %s but the stack deploys to %s; the stream create fails with an AccessDeniedException on the pass role", [acct, data.cdk_preflight.deploy_account]),
	"Use a role in the deploy account",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ExtendedS3DestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	arn := object.get(c, "RoleARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:aws")
	parts := split(arn, ":")
	count(parts) > 4
	acct := parts[4]
	regex.match(`^[0-9]{12}$`, acct)
	acct != data.cdk_preflight.deploy_account
}
