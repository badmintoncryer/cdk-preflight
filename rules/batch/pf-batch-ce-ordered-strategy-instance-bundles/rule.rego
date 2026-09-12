package cdk_preflight

import rego.v1

# Both ordered strategies scale in the order instanceTypes lists,
# which a bundle such as optimal cannot express.
violation contains make_diag_full("pf-batch-ce-ordered-strategy-instance-bundles", "ERROR", name,
	"Properties.ComputeResources.InstanceTypes",
	sprintf("allocation strategy %v lists the instance type bundle %v (\"Instance type bundles (e.g. optimal, default_x86_64) are not allowed for %v allocation strategy. Specify instance families or types directly.\")", [s, v, s]),
	"List instance families or instance types in preference order",
	"https://docs.aws.amazon.com/batch/latest/userguide/allocation-strategies.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	s := _pf_batch_crget(name, "AllocationStrategy")
	s in {"BEST_FIT_PROGRESSIVE_ORDERED", "SPOT_CAPACITY_OPTIMIZED_PRIORITIZED"}
	some v in _pf_batch_ce_itypes(name)
	regex.match(`^(optimal|default_)`, v)
}
