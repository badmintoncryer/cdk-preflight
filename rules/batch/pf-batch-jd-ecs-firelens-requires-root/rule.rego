package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-firelens-requires-root", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"the task element configures Firelens but no container runs as root (\"When a firelensConfiguration object is specified, at least one container has to run as root\")",
	"Drop User, or set it to root (0) on one container",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-job-definition-single-node-multi-container.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	cs := object.get(t.value, "Containers", [])
	some c in cs
	_pf_batch_ohas(c, "FirelensConfiguration")
	count([1 | some x in cs; object.get(x, "User", "root") in {"root", "0"}]) == 0
}
