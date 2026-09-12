package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-unmanaged-service-linked-role", "ERROR", name,
	"Properties.ServiceRole",
	sprintf("Type UNMANAGED uses the service-linked role %v (\"Service Linked Role cannot be used with UNMANAGED Compute Environment\")", [sr]),
	"Point ServiceRole at a customer-managed Batch service role",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_get(name, "Type") == "UNMANAGED"
	sr := _pf_batch_get(name, "ServiceRole")
	_pf_batch_lit(sr)
	_pf_batch_slr(sr)
}
