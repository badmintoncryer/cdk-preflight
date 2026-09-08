package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-role-without-load-balancers", "ERROR", name,
	"Properties.Role",
	"The service sets Role without any LoadBalancers; CreateService fails with \"IAM roles are only valid for services configured to use load balancers\"",
	"Drop Role, or attach a load balancer",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	_pf_ecs_has(name, "Role")
	not _pf_ecs_has(name, "LoadBalancers")
}
