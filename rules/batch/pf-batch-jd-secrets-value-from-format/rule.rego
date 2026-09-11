package cdk_preflight

import rego.v1

# An ARN is checked for its service segment only: Parameter Store also accepts
# a bare parameter name, so a non-ARN value cannot be judged here.
violation contains make_diag_full("pf-batch-jd-secrets-value-from-format", "ERROR", name,
	"Properties.ContainerProperties.Secrets",
	sprintf("secret %v reads from %v, which is neither a Secrets Manager secret nor an SSM parameter", [object.get(s.value, "Name", s.index), v]),
	"Use a secretsmanager or ssm ARN (or a Parameter Store parameter name)",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Secret.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some s in flatten_list(name, "Properties.ContainerProperties.Secrets")
	v := _pf_batch_oget(s.value, "ValueFrom")
	_pf_batch_lit(v)
	startswith(v, "arn:")
	svc := split(v, ":")[2]
	not svc in {"secretsmanager", "ssm"}
}
