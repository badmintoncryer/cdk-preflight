package cdk_preflight

import rego.v1

# EventBridge invokes Lambda, SNS, SQS and CloudWatch Logs through a
# resource-based policy, so those four take no RoleArn. Every other supported
# target service is invoked by assuming a role, and PutTargets rejects the
# entry when RoleArn is absent (measured 2026-09-07, events:PutTargets,
# us-east-1). AppSync is left out of the set: its ARN validation runs first,
# so the RoleArn requirement could not be observed directly.
_pf_evtrole_services := {
	"batch", "codebuild", "codepipeline", "ecs", "events", "firehose",
	"glue", "inspector", "kinesis", "redshift", "sagemaker", "ssm",
	"ssm-incidents", "states",
}

_pf_evtrole_service(arn) := s if {
	parts := split(arn, ":")
	count(parts) > 2
	s := parts[2]
}

violation contains make_diag_full("pf-events-target-role-required", "ERROR", name,
	sprintf("Properties.Targets.%d.RoleArn", [t.index]),
	sprintf("Target '%s' is a %s target, which EventBridge can only invoke by assuming a role; PutTargets fails with \"RoleArn is required for target %s\"", [tid, svc, arn]),
	"Set RoleArn on the target to a role EventBridge can assume",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	arn := object.get(t.value, "Arn", null)
	is_string(arn)
	svc := _pf_evtrole_service(arn)
	svc in _pf_evtrole_services
	object.get(t.value, "RoleArn", "__pf_absent") == "__pf_absent"
	tid := object.get(t.value, "Id", "<target>")
}
