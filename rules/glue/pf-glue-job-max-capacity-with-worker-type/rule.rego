package cdk_preflight

import rego.v1

# CreateJob rejects the two allocation models together. Only the full pair
# trips it; one half alone is a different error (see
# pf-glue-job-worker-type-and-number-of-workers).
violation contains make_diag_full("pf-glue-job-max-capacity-with-worker-type", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity %v is set alongside WorkerType and NumberOfWorkers; CreateJob accepts one allocation model, not both", [mc]),
	"Drop MaxCapacity and keep WorkerType + NumberOfWorkers, or drop those two and keep MaxCapacity",
	"https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	mc := _pf_gluelib_get(name, "MaxCapacity")
	_pf_gluelib_has(name, "WorkerType")
	_pf_gluelib_has(name, "NumberOfWorkers")
}
