package cdk_preflight

import rego.v1

# EventBridge assumes a target's RoleArn each time the rule fires, and PutTargets
# does not check that it can. A role whose trust policy does not name
# events.amazonaws.com deploys and then every invocation fails (FailedInvocations,
# or a dead-letter message when the target has one). Lambda, SNS, SQS and Logs
# targets are reached through their resource policies and ignore RoleArn, so only
# targets that are visibly one of the kinds EventBridge calls with the role are
# judged. ECS was measured on bench; the rest are the role-assumed targets in the
# EventBridge permissions doc. An event bus target is left out: whether a
# same-account bus uses RoleArn or its own resource policy is not confirmed.
_pf_evrt_role_services := {"ecs", "states", "kinesis", "firehose", "codebuild", "codepipeline", "batch"}

_pf_evrt_role_types := {
	"AWS::ECS::Cluster", "AWS::StepFunctions::StateMachine", "AWS::Kinesis::Stream",
	"AWS::KinesisFirehose::DeliveryStream", "AWS::CodeBuild::Project",
	"AWS::CodePipeline::Pipeline", "AWS::Batch::JobQueue",
}

_pf_evrt_uses_role(arn) if {
	is_string(arn)
	startswith(arn, "arn:")
	split(arn, ":")[2] in _pf_evrt_role_services
}

_pf_evrt_uses_role(arn) if {
	is_object(arn)
	ref := object.get(arn, "__ref", null)
	some t in _pf_evrt_role_types
	ref in resources_of_type(t)
}
violation contains make_diag_full("pf-events-target-role-trust", "ERROR", name,
	sprintf("Properties.Targets.%d.RoleArn", [i]),
	sprintf("Target '%s' uses role '%s', whose trust policy does not let events.amazonaws.com assume it; every invocation of this target fails", [object.get(t, "Id", "<target>"), role]),
	sprintf("Add events.amazonaws.com to the Service principals of %s's AssumeRolePolicyDocument", [role]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-identity-based.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	props := input.resources[name].properties
	is_object(props)
	ts := object.get(props, "Targets", null)
	is_array(ts)
	some i, t in ts
	is_object(t)
	_pf_evrt_uses_role(object.get(t, "Arn", null))
	role := _pf_iamlib_role_without_service(object.get(t, "RoleArn", null), "events.amazonaws.com")
}
