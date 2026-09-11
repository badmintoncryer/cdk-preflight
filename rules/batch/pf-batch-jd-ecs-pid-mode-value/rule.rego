package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-pid-mode-value", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("PidMode %v is not valid (\"Capability %v is not valid. Valid capabilities: [host, task]\")", [m, m]),
	"Use host or task",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EcsTaskProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	m := _pf_batch_oget(t.value, "PidMode")
	_pf_batch_lit(m)
	not m in {"host", "task"}
}
