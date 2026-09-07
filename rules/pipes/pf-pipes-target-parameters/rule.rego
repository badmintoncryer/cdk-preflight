package cdk_preflight

import rego.v1

# "Invalid target parameter provided for target." — CreatePipe matches the
# TargetParameters block against the target ARN's service. Table measured
# 2026-09-07, pipes:CreatePipe, us-east-1, by creating each block on its own
# matching target. InputTemplate is not a target-type block and is excluded.
_pf_pipetgt_allowed := {
	"LambdaFunctionParameters": {"lambda"},
	"StepFunctionStateMachineParameters": {"states"},
	"KinesisStreamParameters": {"kinesis"},
	"EcsTaskParameters": {"ecs"},
	"BatchJobParameters": {"batch"},
	"SqsQueueParameters": {"sqs"},
	"EventBridgeEventBusParameters": {"events"},
	"HttpParameters": {"events", "execute-api"},
	"RedshiftDataParameters": {"redshift", "redshift-serverless"},
	"SageMakerPipelineParameters": {"sagemaker"},
	"CloudWatchLogsParameters": {"logs"},
	"TimestreamParameters": {"timestream"},
}

_pf_pipetgt_service(name) := parts[2] if {
	arn := resolve(name, "Properties.Target")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
}

violation contains make_diag_full("pf-pipes-target-parameters", "ERROR", name,
	sprintf("Properties.TargetParameters.%s", [block]),
	sprintf("%s only applies to a %v target but the pipe writes to %s; CreatePipe fails with \"Invalid target parameter provided for target\"", [block, sort(allowed), svc]),
	sprintf("Remove %s, or point Target at a matching resource", [block]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-pipes-pipe-pipetargetparameters.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	tp := input.resources[name].properties.TargetParameters
	is_object(tp)
	some block, allowed in _pf_pipetgt_allowed
	object.get(tp, block, "__pf_absent") != "__pf_absent"
	svc := _pf_pipetgt_service(name)
	not svc in allowed
}
