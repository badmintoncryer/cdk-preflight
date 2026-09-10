package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-secrets-manager-secret-arn", "ERROR", name,
	sprintf("%s.SecretsManagerConfiguration.SecretARN", [path]),
	"the Secrets Manager configuration is enabled but carries no SecretARN; the stream create fails with \"Invalid secret ARN: null\"",
	"Set SecretARN, or disable the Secrets Manager configuration",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SecretsManagerConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	s := object.get(c, "SecretsManagerConfiguration", null)
	is_object(s)
	coerce_to_bool(object.get(s, "Enabled", false)) == true
	object.get(s, "SecretARN", "__pf_absent") == "__pf_absent"
}
