package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-scheduling-policy-arn-region", "ERROR", name,
	"Properties.SchedulingPolicyArn",
	sprintf("the scheduling policy is in %v but the job queue deploys to %v (\"SchedulingPolicy ... not found.\")", [r, data.cdk_preflight.deploy_region]),
	"Reference a scheduling policy from the same region as the queue",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	r := _pf_batch_region_mismatch(resolve(name, "Properties.SchedulingPolicyArn"))
}
