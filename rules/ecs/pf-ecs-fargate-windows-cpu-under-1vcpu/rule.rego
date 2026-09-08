package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-windows-cpu-under-1vcpu", "ERROR", name,
	"Properties.Cpu",
	sprintf("A Windows (%s) FARGATE task definition allocates %v CPU units; Windows containers need at least 1024 and RegisterTaskDefinition fails with \"No Fargate configuration exists for given values\"", [os, cpu]),
	"Set Cpu to 1024 or more for a Windows Fargate task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	os := resolve(name, "Properties.RuntimePlatform.OperatingSystemFamily")
	startswith(os, "WINDOWS")
	cpu := to_number(resolve(name, "Properties.Cpu"))
	cpu < 1024
}
