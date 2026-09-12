package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-security-groups-required", "ERROR", name,
	"Properties.ComputeResources.SecurityGroupIds",
	sprintf("ComputeResources.Type %v lists no security group and no launch template (\"Security group ids are required.\")", [t]),
	"List at least one security group, or supply one from a launch template",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	t := _pf_batch_crtype(name)
	t != "ECS_MANAGED_INSTANCES"
	count(_pf_batch_ce_sgs(name)) == 0
	not _pf_batch_lt(name)
}
