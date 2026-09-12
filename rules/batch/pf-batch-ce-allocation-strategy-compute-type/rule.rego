package cdk_preflight

import rego.v1

# The SPOT_* strategies and BEST_FIT_PROGRESSIVE_ORDERED each bind to one
# purchase model; BEST_FIT and BEST_FIT_PROGRESSIVE work on both.
violation contains make_diag_full("pf-batch-ce-allocation-strategy-compute-type", "ERROR", name,
	"Properties.ComputeResources.AllocationStrategy",
	sprintf("allocation strategy %v on ComputeResources.Type %v; it is only available for %v resources", [s, t, want]),
	"Match the strategy to the purchase model, or change ComputeResources.Type",
	"https://docs.aws.amazon.com/batch/latest/userguide/allocation-strategies.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	s := _pf_batch_crget(name, "AllocationStrategy")
	_pf_batch_lit(s)
	t := _pf_batch_crtype(name)
	want := _pf_batch_alloc_type(s)
	t != want
}
