package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-depends-on-condition-value", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("%v is not a container dependency condition (\"TaskContainer dependency %v is not valid. Valid values are: [START, COMPLETE, SUCCESS]\")", [cond, cond]),
	"Use START, COMPLETE or SUCCESS",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_TaskContainerDependency.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	some c in object.get(t.value, "Containers", [])
	some d in object.get(c, "DependsOn", [])
	cond := object.get(d, "Condition", null)
	_pf_batch_lit(cond)
	not cond in {"START", "COMPLETE", "SUCCESS"}
}
