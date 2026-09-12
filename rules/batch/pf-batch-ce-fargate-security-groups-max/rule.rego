package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-fargate-security-groups-max", "ERROR", name,
	"Properties.ComputeResources.SecurityGroupIds",
	sprintf("Fargate compute resources list %v security groups (\"Fargate supports a maximum of 5 security groups.\")", [n]),
	"Attach at most 5 security groups",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_fargate(name)
	n := count(_pf_batch_ce_sgs(name))
	n > 5
}
