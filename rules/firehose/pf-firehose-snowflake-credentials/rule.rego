package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-snowflake-credentials", "ERROR", name,
	"Properties.SnowflakeDestinationConfiguration.PrivateKey",
	"PrivateKey is not set and no Secrets Manager configuration is enabled; the stream create fails with \"PrivateKey must be provided.\"",
	"Set PrivateKey, or enable SecretsManagerConfiguration with a SecretARN",
	"https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SnowflakeDestinationConfiguration"
	object.get(c, "PrivateKey", "__pf_absent") == "__pf_absent"
	not _pf_fhcred_secret(c)
}
