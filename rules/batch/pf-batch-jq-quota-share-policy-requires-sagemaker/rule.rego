package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-quota-share-policy-requires-sagemaker", "ERROR", name,
	"Properties.SchedulingPolicyArn",
	sprintf("a %v job queue uses a scheduling policy with a QuotaSharePolicy (\"Quota Management feature is only supported for SageMaker Training job queues.\")", [t]),
	"Attach the quota scheduling policy to a SAGEMAKER_TRAINING job queue, or use a FairsharePolicy",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-quota-management-resources.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	t := _pf_batch_qtype(name)
	t != "SAGEMAKER_TRAINING"
	sp := resolve(name, "Properties.SchedulingPolicyArn")
	p := _pf_batch_props(sp)
	_pf_batch_ohas(p, "QuotaSharePolicy")
}
