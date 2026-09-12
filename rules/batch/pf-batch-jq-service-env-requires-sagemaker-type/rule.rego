package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-service-env-requires-sagemaker-type", "ERROR", name,
	"Properties.ServiceEnvironmentOrder",
	sprintf("a %v job queue attaches a service environment (\"The jobQueueType provided is %v, which is incompatible with the provided serviceEnvironmentOrder.\")", [t, t]),
	"Set JobQueueType: SAGEMAKER_TRAINING, or attach compute environments instead",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-sagemaker-job-queue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	_pf_batch_has(name, "ServiceEnvironmentOrder")
	t := _pf_batch_qtype(name)
	t != "SAGEMAKER_TRAINING"
}
