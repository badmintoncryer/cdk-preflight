package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-proxy-configuration-container-missing", "ERROR", name,
	"Properties.ProxyConfiguration.ContainerName",
	sprintf("ProxyConfiguration points at the container '%s', which the task definition does not declare; RegisterTaskDefinition fails with \"Proxy container [%s] does not exist\"", [cn, cn]),
	"Point ContainerName at the App Mesh proxy container declared in this task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	pc := _pf_ecs_get(name, "ProxyConfiguration")
	cn := _pf_ecs_oget(pc, "ContainerName")
	_pf_ecs_lit(cn)
	not cn in _pf_ecs_names(name)
}
