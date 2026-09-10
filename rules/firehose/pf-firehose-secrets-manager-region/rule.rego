package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-secrets-manager-region", "ERROR", name,
	sprintf("%s.SecretsManagerConfiguration.SecretARN", [path]),
	sprintf("the secret is in %s but the stack deploys to %s; the stream create fails with \"Cross-region secrets are not allowed. Please provide a secret in the same region as firehose\"", [r, data.cdk_preflight.deploy_region]),
	"Replicate the secret into the Firehose region and point SecretARN at that copy",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SecretsManagerConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	s := object.get(c, "SecretsManagerConfiguration", null)
	is_object(s)
	arn := object.get(s, "SecretARN", null)
	_pf_fhlib_lit(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) > 3
	r := parts[3]
	count(r) > 0
	r != data.cdk_preflight.deploy_region
}
