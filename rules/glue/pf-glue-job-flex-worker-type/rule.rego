package cdk_preflight

import rego.v1

# The same CreateJob message also rejects a FLEX job with no WorkerType at
# all; that half is not covered here because a MaxCapacity-sized FLEX job
# was not measured on a real stack.
violation contains make_diag_full("pf-glue-job-flex-worker-type", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType %v on a FLEX job; flexible execution supports G.1X and G.2X only", [wt]),
	"Use G.1X or G.2X, or set ExecutionClass to STANDARD",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_str(name, "Properties.ExecutionClass") == "FLEX"
	wt := _pf_gluelib_worker_type(name)
	not wt in {"G.1X", "G.2X"}
}
