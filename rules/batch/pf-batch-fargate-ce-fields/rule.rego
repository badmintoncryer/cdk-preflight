package cdk_preflight

import rego.v1

_pf_batchfcf_cr(name) := cr if {
	cr := resolve(name, "Properties.ComputeResources.Type")
	is_string(cr)
}

violation contains make_diag_full("pf-batch-fargate-ce-fields", "ERROR", name,
	sprintf("Properties.ComputeResources.%s", [field]),
	sprintf("%s is not applicable for %s compute environments; Batch rejects the create call", [field, cr]),
	"Remove the EC2-only field, or switch ComputeResources.Type to EC2/SPOT",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	cr := _pf_batchfcf_cr(name)
	cr in {"FARGATE", "FARGATE_SPOT"}
	cres := input.resources[name].properties.ComputeResources
	is_object(cres)
	# Every compute resource field Batch answers with "<field> is not applicable
	# for Fargate."; one service check, so one rule.
	some field in {
		"AllocationStrategy", "BidPercentage", "DesiredvCpus", "Ec2KeyPair",
		"ImageId", "InstanceRole", "InstanceTypes", "LaunchTemplate",
		"MinvCpus", "PlacementGroup", "SpotIamFleetRole", "Tags",
	}
	object.get(cres, field, "__pf_absent") != "__pf_absent"
}
