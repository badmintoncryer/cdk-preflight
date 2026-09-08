package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-min-healthy-over-max-percent", "ERROR", name,
	"Properties.DeploymentConfiguration",
	sprintf("The rolling update leaves no room to replace tasks: MinimumHealthyPercent %v and MaximumPercent %v; CreateService fails with \"Both maximumPercent and minimumHealthyPercent cannot be 100 as this will block deployments\"", [mn, mx]),
	"Raise MaximumPercent above MinimumHealthyPercent (for example 100 / 200)",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	dc := _pf_ecs_get(name, "DeploymentConfiguration")
	mn := to_number(_pf_ecs_oget(dc, "MinimumHealthyPercent"))
	mx := to_number(_pf_ecs_oget(dc, "MaximumPercent"))
	mn >= mx
}
