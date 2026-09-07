package cdk_preflight

import rego.v1

# "Region of <cluster arn> does not match region of <task definition arn>" —
# the cluster and its task definition must live together. Measured
# 2026-09-07, events:PutTargets, us-east-1. This is a cross-property check
# inside one target, so it needs no deploy region.
_pf_evecsr_region(arn) := parts[3] if {
	parts := split(arn, ":")
	count(parts) > 3
	parts[3] != ""
}

violation contains make_diag_full("pf-events-target-ecs-task-definition-region", "ERROR", name,
	sprintf("Properties.Targets.%d.EcsParameters.TaskDefinitionArn", [t.index]),
	sprintf("The cluster is in '%s' but the task definition is in '%s'; PutTargets fails with \"Region of %s does not match region of %s\"", [cr, tr, carn, tarn]),
	"Reference a task definition in the cluster's Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	some t in flatten_list(name, "Properties.Targets")
	is_object(t.value)
	carn := object.get(t.value, "Arn", null)
	is_string(carn)
	ecs := object.get(t.value, "EcsParameters", null)
	is_object(ecs)
	tarn := object.get(ecs, "TaskDefinitionArn", null)
	is_string(tarn)
	cr := _pf_evecsr_region(carn)
	tr := _pf_evecsr_region(tarn)
	cr != tr
}
