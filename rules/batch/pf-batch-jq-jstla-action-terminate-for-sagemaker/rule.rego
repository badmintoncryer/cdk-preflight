package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-jstla-action-terminate-for-sagemaker", "ERROR", name,
	"Properties.JobStateTimeLimitActions",
	sprintf("a SAGEMAKER_TRAINING job queue asks for the %v action (\"Invalid job action. Valid job actions: [TERMINATE]\")", [act]),
	"Use Action: TERMINATE on SAGEMAKER_TRAINING job queues",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_JobStateTimeLimitAction.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	_pf_batch_qtype(name) == "SAGEMAKER_TRAINING"
	some a in flatten_list(name, "Properties.JobStateTimeLimitActions")
	act := _pf_batch_oget(a.value, "Action")
	_pf_batch_lit(act)
	act != "TERMINATE"
}
