package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-role-with-awsvpc", "ERROR", name,
	"Properties.Role",
	"The service sets Role while using the awsvpc network mode; CreateService fails with \"You cannot specify an IAM role for services that require a service linked role\"",
	"Drop Role; ECS uses the service-linked role for awsvpc services",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	_pf_ecs_has(name, "Role")
	_pf_ecs_has(name, "NetworkConfiguration")
}
