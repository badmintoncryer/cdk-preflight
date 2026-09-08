package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-registries-port-with-awsvpc", "ERROR", name,
	"Properties.ServiceRegistries",
	"An awsvpc service sets ContainerName / ContainerPort on its service registry; CreateService fails with \"The values specified for serviceRegistries do not require a value for 'containerPort'\"",
	"Drop ContainerName and ContainerPort; use Port instead",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	_pf_ecs_has(name, "NetworkConfiguration")
	some sr in flatten_list(name, "Properties.ServiceRegistries")
	some k in {"ContainerName", "ContainerPort"}
	_pf_ecs_ohas(sr.value, k)
}
