package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-unmanaged-service-role", "ERROR", name,
	"Properties.ServiceRole",
	"Type UNMANAGED without ServiceRole (\"ServiceRole is required.\"); the service only creates its service-linked role for MANAGED environments",
	"Set ServiceRole to the ARN of a Batch service role",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_get(name, "Type") == "UNMANAGED"
	not _pf_batch_has(name, "ServiceRole")
}
