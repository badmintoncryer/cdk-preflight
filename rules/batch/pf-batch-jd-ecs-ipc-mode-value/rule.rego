package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-ipc-mode-value", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("IpcMode %v is not valid (\"ipcMode %v is not valid. Valid values are: [host, task, none]\")", [m, m]),
	"Use host, task or none",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EcsTaskProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	m := _pf_batch_oget(t.value, "IpcMode")
	_pf_batch_lit(m)
	not m in {"host", "task", "none"}
}
