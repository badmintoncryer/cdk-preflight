package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-spot-fleet-role", "ERROR", name,
	"Properties.ComputeResources.SpotIamFleetRole",
	"SPOT compute resources on the BEST_FIT allocation strategy (the default) without SpotIamFleetRole (\"compute resource spotIamFleetRole is required.\")",
	"Set SpotIamFleetRole, or pick a BEST_FIT_PROGRESSIVE / SPOT_* allocation strategy",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	_pf_batch_crtype(name) == "SPOT"
	_pf_batch_ce_bestfit(name)
	not _pf_batch_crhas(name, "SpotIamFleetRole")
}
