package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-instance-role-required", "ERROR", name,
	"Properties.ComputeResources.InstanceRole",
	sprintf("ComputeResources.Type %v without InstanceRole (\"Instance role is required.\")", [t]),
	"Set InstanceRole to an ECS instance profile ARN",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_ec2(name)
	t := _pf_batch_crtype(name)
	not _pf_batch_crhas(name, "InstanceRole")
}
