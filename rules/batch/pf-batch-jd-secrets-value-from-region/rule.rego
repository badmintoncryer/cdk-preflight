package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-secrets-value-from-region", "ERROR", name,
	"Properties.ContainerProperties.Secrets",
	sprintf("secret %v is in %v but the stack deploys to %v", [object.get(s.value, "Name", s.index), region, data.cdk_preflight.deploy_region]),
	"Reference a secret in the deployment Region",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Secret.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some s in flatten_list(name, "Properties.ContainerProperties.Secrets")
	v := _pf_batch_oget(s.value, "ValueFrom")
	_pf_batch_lit(v)
	parts := split(v, ":")
	parts[0] == "arn"
	parts[2] in {"secretsmanager", "ssm"}
	region := parts[3]
	region != ""
	region != data.cdk_preflight.deploy_region
}
