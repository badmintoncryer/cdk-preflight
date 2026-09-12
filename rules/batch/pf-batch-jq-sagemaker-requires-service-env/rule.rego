package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-sagemaker-requires-service-env", "ERROR", name,
	"Properties.ServiceEnvironmentOrder",
	"a SAGEMAKER_TRAINING job queue has no ServiceEnvironmentOrder (\"Job queues of type SAGEMAKER_TRAINING must have serviceEnvironmentOrder.\")",
	"Attach a service environment through ServiceEnvironmentOrder",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-sagemaker-job-queue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	_pf_batch_qtype(name) == "SAGEMAKER_TRAINING"
	not _pf_batch_has(name, "ServiceEnvironmentOrder")
}
