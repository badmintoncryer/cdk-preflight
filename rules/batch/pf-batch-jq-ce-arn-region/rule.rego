package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-ce-arn-region", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	sprintf("a compute environment in %v is attached to a job queue deploying to %v (\"Compute Environments must be created and valid before attaching them to a job queue\")", [r, data.cdk_preflight.deploy_region]),
	"Attach a compute environment from the same region as the queue",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	some e in flatten_list(name, "Properties.ComputeEnvironmentOrder")
	r := _pf_batch_region_mismatch(_pf_batch_oget(e.value, "ComputeEnvironment"))
}
