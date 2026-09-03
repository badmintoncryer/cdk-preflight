package cdk_preflight

import rego.v1

_pf_batchumf_cr(name) := cr if {
	cr := resolve(name, "Properties.ComputeResources.Type")
	is_string(cr)
}

violation contains make_diag_full("pf-batch-unmanaged-fargate", "ERROR", name,
	"Properties.ComputeResources.Type",
	sprintf("Type UNMANAGED cannot pair with ComputeResources.Type %s (\"Cannot create an UNMANAGED Fargate Compute Environment.\")", [cr]),
	"Use MANAGED for Fargate, or EC2 resources for UNMANAGED",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	resolve(name, "Properties.Type") == "UNMANAGED"
	cr := _pf_batchumf_cr(name)
	cr in {"FARGATE", "FARGATE_SPOT"}
}
