package cdk_preflight

import rego.v1

# Re-aimed 2026-09-12: the documented "one container has to run as root" is
# not what RegisterJobDefinition checks — it asks for the awsfirelens driver.
violation contains make_diag_full("pf-batch-jd-ecs-firelens-log-driver", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"the task element configures Firelens but no container uses the awsfirelens log driver (\"When a firelensConfiguration object is specified, at least one container has to be configured with the awsfirelens log driver\")",
	"Send one container's logs through LogConfiguration.LogDriver: awsfirelens",
	"https://docs.aws.amazon.com/batch/latest/userguide/multi-container-jobs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	cs := object.get(t.value, "Containers", [])
	some c in cs
	_pf_batch_ohas(c, "FirelensConfiguration")
	count([1 | some x in cs; object.get(object.get(x, "LogConfiguration", {}), "LogDriver", "") == "awsfirelens"]) == 0
}
