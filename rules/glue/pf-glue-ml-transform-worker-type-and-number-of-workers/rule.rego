package cdk_preflight

import rego.v1

# Either half on its own is rejected with the same sentence, so both directions
# are checked.
violation contains make_diag_full("pf-glue-ml-transform-worker-type-and-number-of-workers", "ERROR", name,
	"Properties.NumberOfWorkers",
	sprintf("WorkerType %v is set but NumberOfWorkers is missing; CreateMLTransform fails with \"Both WorkerType and NumberOfWorkers should be set\"", [wt]),
	"Add NumberOfWorkers, or size the transform with MaxCapacity instead",
	"https://docs.aws.amazon.com/glue/latest/dg/machine-learning.html") if {
	some name in resources_of_type("AWS::Glue::MLTransform")
	wt := _pf_gluelib_get(name, "WorkerType")
	_pf_gluelib_absent(name, "NumberOfWorkers")
}

violation contains make_diag_full("pf-glue-ml-transform-worker-type-and-number-of-workers", "ERROR", name,
	"Properties.WorkerType",
	sprintf("NumberOfWorkers %v is set but WorkerType is missing; CreateMLTransform fails with \"Both WorkerType and NumberOfWorkers should be set\"", [nw]),
	"Add WorkerType, or size the transform with MaxCapacity instead",
	"https://docs.aws.amazon.com/glue/latest/dg/machine-learning.html") if {
	some name in resources_of_type("AWS::Glue::MLTransform")
	nw := _pf_gluelib_get(name, "NumberOfWorkers")
	_pf_gluelib_absent(name, "WorkerType")
}
