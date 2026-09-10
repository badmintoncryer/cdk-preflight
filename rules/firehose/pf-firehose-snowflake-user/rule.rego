package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-snowflake-user", "ERROR", name,
	"Properties.SnowflakeDestinationConfiguration.User",
	"User is not set and no Secrets Manager configuration is enabled; the stream create fails with \"User must be provided.\"",
	"Set User, or enable SecretsManagerConfiguration with a SecretARN",
	"https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SnowflakeDestinationConfiguration"
	object.get(c, "User", "__pf_absent") == "__pf_absent"
	not _pf_fhcred_secret(c)
}
