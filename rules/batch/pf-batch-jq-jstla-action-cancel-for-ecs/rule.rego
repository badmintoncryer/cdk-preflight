package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-jstla-action-cancel-for-ecs", "ERROR", name,
	"Properties.JobStateTimeLimitActions",
	sprintf("a %v job queue asks for the %v action (\"Invalid job action. Valid job actions: [CANCEL]\")", [t, act]),
	"Use Action: CANCEL on ECS, FARGATE and EKS job queues",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_JobStateTimeLimitAction.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	t := _pf_batch_qtype(name)
	t != "SAGEMAKER_TRAINING"
	some a in flatten_list(name, "Properties.JobStateTimeLimitActions")
	act := _pf_batch_oget(a.value, "Action")
	_pf_batch_lit(act)
	act != "CANCEL"
}
