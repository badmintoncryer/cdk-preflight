package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-windows-arm64", "ERROR", name,
	"Properties.RuntimePlatform.CpuArchitecture",
	sprintf("RuntimePlatform pairs the Windows family '%s' with CpuArchitecture ARM64; no Fargate configuration exists for that pair and RegisterTaskDefinition fails", [os]),
	"Use X86_64 with a Windows operating system family",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	os := resolve(name, "Properties.RuntimePlatform.OperatingSystemFamily")
	startswith(os, "WINDOWS")
	resolve(name, "Properties.RuntimePlatform.CpuArchitecture") == "ARM64"
}
