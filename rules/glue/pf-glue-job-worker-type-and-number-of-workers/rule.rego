package cdk_preflight

import rego.v1

# CreateJob rejects either half on its own with one message, so both
# directions are checked. Absence is read off the raw document: resolve() is
# also undefined for a present-but-unresolvable value.
violation contains make_diag_full("pf-glue-job-worker-type-and-number-of-workers", "ERROR", name,
	"Properties.NumberOfWorkers",
	sprintf("WorkerType %v is set but NumberOfWorkers is missing; CreateJob needs both", [wt]),
	"Add NumberOfWorkers (at least 2), or size the job with MaxCapacity instead",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	wt := _pf_gluelib_get(name, "WorkerType")
	_pf_gluelib_absent(name, "NumberOfWorkers")
}

violation contains make_diag_full("pf-glue-job-worker-type-and-number-of-workers", "ERROR", name,
	"Properties.WorkerType",
	sprintf("NumberOfWorkers %v is set but WorkerType is missing; CreateJob needs both", [nw]),
	"Add WorkerType, or size the job with MaxCapacity instead",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	nw := _pf_gluelib_get(name, "NumberOfWorkers")
	_pf_gluelib_absent(name, "WorkerType")
}
