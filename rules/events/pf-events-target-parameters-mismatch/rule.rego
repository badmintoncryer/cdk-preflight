package cdk_preflight

import rego.v1

# PutTargets rejects a target-type parameter block that does not match the
# target's ARN ("Parameter(s) EcsParameters not supported for target: t1").
# Measured 2026-09-07, events:PutTargets, us-east-1. SqsParameters is
# deliberately absent from the table: it is accepted on any target type.
_pf_evtpm_allowed := {
	"EcsParameters": {"ecs"},
	"KinesisParameters": {"kinesis"},
	"BatchParameters": {"batch"},
	"HttpParameters": {"events", "execute-api"},
	"RedshiftDataParameters": {"redshift", "redshift-serverless"},
	"RunCommandParameters": {"ssm"},
	"SageMakerPipelineParameters": {"sagemaker"},
	"AppSyncParameters": {"appsync"},
}

_pf_evtpm_service(arn) := parts[2] if {
	parts := split(arn, ":")
	count(parts) > 2
}

violation contains make_diag_full("pf-events-target-parameters-mismatch", "ERROR", name,
	sprintf("Properties.Targets.%d.%s", [t.index, block]),
	sprintf("%s is only valid on a %v target but '%s' points at %s; PutTargets fails with \"Parameter(s) %s not supported for target: %s\"", [block, sort(allowed), tid, arn, block, tid]),
	sprintf("Remove %s, or point the target at a matching resource", [block]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	some block, allowed in _pf_evtpm_allowed
	object.get(t.value, block, "__pf_absent") != "__pf_absent"
	arn := object.get(t.value, "Arn", null)
	is_string(arn)
	not _pf_evtpm_service(arn) in allowed
	tid := object.get(t.value, "Id", "<target>")
}
