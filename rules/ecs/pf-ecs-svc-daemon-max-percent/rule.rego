package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-daemon-max-percent", "ERROR", name,
	"Properties.DeploymentConfiguration.MaximumPercent",
	sprintf("A DAEMON service sets MaximumPercent to %v; CreateService fails with \"The daemon scheduling strategy does not support values above 100 for maximumPercent\"", [mp]),
	"Set MaximumPercent to 100 for DAEMON services",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.SchedulingStrategy") == "DAEMON"
	mp := to_number(resolve(name, "Properties.DeploymentConfiguration.MaximumPercent"))
	mp > 100
}
