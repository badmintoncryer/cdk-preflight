package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-proxy-configuration-awsvpc-required", "ERROR", name,
	"Properties.NetworkMode",
	sprintf("The task definition declares an App Mesh ProxyConfiguration with NetworkMode '%s'; RegisterTaskDefinition fails with \"APPMESH proxy configuration is only supported in networkMode=awsvpc\"", [nm]),
	"Set NetworkMode to awsvpc, or drop ProxyConfiguration",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_has(name, "ProxyConfiguration")
	nm := resolve(name, "Properties.NetworkMode")
	is_string(nm)
	nm != "awsvpc"
}
