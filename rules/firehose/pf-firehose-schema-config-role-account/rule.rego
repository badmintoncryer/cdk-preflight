package cdk_preflight

import rego.v1

# Only this pack knows the deploy account, so only here can a literal ARN
# be compared against it (see AGENTS.md, deploy_account injection).
violation contains make_diag_full("pf-firehose-schema-config-role-account", "ERROR", name,
	sprintf("%s.DataFormatConversionConfiguration.SchemaConfiguration.RoleARN", [path]),
	sprintf("the schema configuration role lives in account %s but the stack deploys to %s; the stream create fails with \"Cross-account pass role is not allowed.\"", [acct, data.cdk_preflight.deploy_account]),
	"Use a role in the deploy account for the Glue schema lookup",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SchemaConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	sc := object.get(object.get(c, "DataFormatConversionConfiguration", {}), "SchemaConfiguration", null)
	is_object(sc)
	arn := object.get(sc, "RoleARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) > 4
	acct := parts[4]
	regex.match(`^[0-9]{12}$`, acct)
	acct != data.cdk_preflight.deploy_account
}
