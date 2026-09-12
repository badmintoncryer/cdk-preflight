package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-fargate-subnets-max", "ERROR", name,
	"Properties.ComputeResources.Subnets",
	sprintf("Fargate compute resources list %v subnets (\"Fargate supports a maximum of 16 subnets.\")", [n]),
	"Place the compute environment in at most 16 subnets",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_ce_fargate(name)
	n := count(_pf_batch_ce_subnets(name))
	n > 16
}
