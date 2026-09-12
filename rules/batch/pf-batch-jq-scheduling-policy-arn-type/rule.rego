package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-scheduling-policy-arn-type", "ERROR", name,
	"Properties.SchedulingPolicyArn",
	sprintf("SchedulingPolicyArn points at %v (\"Only scheduling policy Arn can be allowed.\")", [res]),
	"Pass the ARN of an AWS::Batch::SchedulingPolicy",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	v := resolve(name, "Properties.SchedulingPolicyArn")
	_pf_batch_lit(v)
	startswith(v, "arn:")
	res := _pf_batch_arn_resource(v)
	not startswith(res, "scheduling-policy/")
}
