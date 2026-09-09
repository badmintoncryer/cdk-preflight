package cdk_preflight

import rego.v1

_pf_asgtpl_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgtpl_ok := {
	"AllocationStrategy", "ClosestToNextInstanceHour", "Default", "Lambda",
	"NewestInstance", "OldestInstance", "OldestLaunchConfiguration", "OldestLaunchTemplate",
}

_pf_asgtpl_valid(v) if v in _pf_asgtpl_ok

_pf_asgtpl_valid(v) if _pf_aslib_arn_service(v) == "lambda"

violation contains make_diag_full("pf-asg-termination-policy-lambda-arn-format", "ERROR", name,
	sprintf("Properties.TerminationPolicies.%d", [i]),
	sprintf("'%s' is neither a published termination policy nor a Lambda function ARN; the group create fails with \"[%s] is not a valid termination policy\"", [v, v]),
	"Use one of the published policy names, or the ARN of a termination-policy Lambda", _pf_asgtpl_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, _ in _pf_aslib_arr(name, ["TerminationPolicies"])
	v := resolve(name, sprintf("Properties.TerminationPolicies.%d", [i]))
	_pf_aslib_lit(v)
	not _pf_asgtpl_valid(v)
}
