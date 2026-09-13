package cdk_preflight

import rego.v1

# Worker types belong to the Spark allocation model; pythonshell has none.
violation contains make_diag_full("pf-glue-job-pythonshell-worker-type", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType %v on a pythonshell job; Python shell jobs are sized with MaxCapacity", [wt]),
	"Remove WorkerType and NumberOfWorkers, and set MaxCapacity to 0.0625 or 1",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job-python.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_command_name(name) == "pythonshell"
	wt := _pf_gluelib_worker_type(name)
}
