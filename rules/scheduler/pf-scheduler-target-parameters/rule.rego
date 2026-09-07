package cdk_preflight

import rego.v1

# CreateSchedule matches the target parameter block against the target ARN's
# service, demands SqsParameters for a FIFO queue, and demands
# NetworkConfiguration for a FARGATE ECS task. Measured 2026-09-07,
# scheduler:CreateSchedule, us-east-1, each block confirmed accepted on its
# own matching target.
_pf_schtp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-scheduler-schedule-target.html"

_pf_schtp_allowed := {
	"EcsParameters": "ecs",
	"EventBridgeParameters": "events",
	"KinesisParameters": "kinesis",
	"SageMakerPipelineParameters": "sagemaker",
	"SqsParameters": "sqs",
}

_pf_schtp_target(name) := t if {
	t := input.resources[name].properties.Target
	is_object(t)
}

_pf_schtp_service(t) := parts[2] if {
	arn := object.get(t, "Arn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
}

_pf_schtp_arn(t) := a if {
	a := object.get(t, "Arn", null)
	is_string(a)
}

violation contains make_diag_full("pf-scheduler-target-parameters", "ERROR", name,
	sprintf("Properties.Target.%s", [block]),
	sprintf("%s only applies to a %s target but the schedule invokes %s; CreateSchedule fails with \"Parameters %s not supported for the target\"", [block, want, svc, block]),
	sprintf("Remove %s, or point Target.Arn at a %s resource", [block, want]),
	_pf_schtp_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := _pf_schtp_target(name)
	some block, want in _pf_schtp_allowed
	object.get(t, block, "__pf_absent") != "__pf_absent"
	svc := _pf_schtp_service(t)
	svc != want
}

violation contains make_diag_full("pf-scheduler-target-parameters", "ERROR", name,
	"Properties.Target.SqsParameters",
	"A FIFO queue target needs SqsParameters.MessageGroupId; CreateSchedule fails with \"Parameters SqsParameters must be specified\"",
	"Add Target.SqsParameters.MessageGroupId",
	_pf_schtp_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := _pf_schtp_target(name)
	arn := _pf_schtp_arn(t)
	_pf_schtp_service(t) == "sqs"
	endswith(arn, ".fifo")
	object.get(t, "SqsParameters", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-scheduler-target-parameters", "ERROR", name,
	"Properties.Target.SqsParameters.MessageGroupId",
	"MessageGroupId only applies to a FIFO queue; CreateSchedule fails with \"Parameters MessageGroupId not valid for the target\"",
	"Drop MessageGroupId, or target a .fifo queue",
	_pf_schtp_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := _pf_schtp_target(name)
	arn := _pf_schtp_arn(t)
	_pf_schtp_service(t) == "sqs"
	not endswith(arn, ".fifo")
	sqp := object.get(t, "SqsParameters", null)
	is_object(sqp)
	object.get(sqp, "MessageGroupId", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-scheduler-target-parameters", "ERROR", name,
	"Properties.Target.EcsParameters.NetworkConfiguration",
	"A FARGATE task needs a NetworkConfiguration; CreateSchedule fails with \"Parameter NetworkConfiguration must be specified for the target when launch type is FARGATE\"",
	"Add EcsParameters.NetworkConfiguration.AwsvpcConfiguration",
	_pf_schtp_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	t := _pf_schtp_target(name)
	ecs := object.get(t, "EcsParameters", null)
	is_object(ecs)
	object.get(ecs, "LaunchType", null) == "FARGATE"
	object.get(ecs, "NetworkConfiguration", "__pf_absent") == "__pf_absent"
}
