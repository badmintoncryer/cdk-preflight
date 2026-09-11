package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-log-awslogs-unknown-option", "ERROR", name,
	"Properties.ContainerProperties.LogConfiguration.Options",
	sprintf("%v is not an awslogs option (\"Log driver awslogs disallows options: %v\")", [k, k]),
	"Remove the option; awslogs takes awslogs-group, awslogs-region, awslogs-stream-prefix, awslogs-datetime-format, awslogs-multiline-pattern and awslogs-create-group",
	"https://docs.aws.amazon.com/batch/latest/userguide/using_awslogs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	lc := _pf_batch_cpget(name, "LogConfiguration")
	object.get(lc, "LogDriver", "") == "awslogs"
	some k, _ in object.get(lc, "Options", {})
	not k in {"awslogs-group", "awslogs-region", "awslogs-stream-prefix", "awslogs-datetime-format", "awslogs-multiline-pattern", "awslogs-create-group"}
}
