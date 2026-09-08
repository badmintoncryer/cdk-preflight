package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-capacity-provider-multiple-base", "ERROR", name,
	"Properties.CapacityProviderStrategy",
	"More than one capacity provider in the strategy sets Base; CreateService fails with \"There are multiple capacity providers in the specified capacity provider strategy with a base value defined\"",
	"Keep Base on a single capacity provider",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	cps := _pf_ecs_get(name, "CapacityProviderStrategy")
	is_array(cps)
	count([x | some x in cps; _pf_ecs_ohas(x, "Base")]) > 1
}
