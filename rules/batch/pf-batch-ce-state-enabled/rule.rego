package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-state-enabled", "ERROR", name,
	"Properties.State",
	sprintf("State is %v at create time (\"Compute Environment must be created in ENABLED state.\")", [s]),
	"Create the environment ENABLED and disable it afterwards",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	s := _pf_batch_get(name, "State")
	_pf_batch_lit(s)
	s != "ENABLED"
}
