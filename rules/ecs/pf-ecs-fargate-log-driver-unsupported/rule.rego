package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-log-driver-unsupported", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LogConfiguration.LogDriver", [c.index]),
	sprintf("Container '%s' uses the '%s' log driver on a FARGATE task definition; RegisterTaskDefinition fails with \"%s is not a valid log driver. Must be one of [awslogs, splunk, awsfirelens]\"", [_pf_ecs_cname(c), d, d]),
	"Use awslogs, splunk or awsfirelens on Fargate",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	lc := _pf_ecs_cget(c, "LogConfiguration")
	d := _pf_ecs_oget(lc, "LogDriver")
	_pf_ecs_lit(d)
	not d in {"awslogs", "splunk", "awsfirelens"}
}
