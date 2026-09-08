package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-capacity-provider-zero-weight", "ERROR", name,
	"Properties.CapacityProviderStrategy",
	"Every capacity provider in the strategy has Weight 0; CreateService fails with \"There are no capacity providers in the capacity provider strategy with a weight value greater than zero\"",
	"Give at least one capacity provider a Weight above 0",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	cps := _pf_ecs_get(name, "CapacityProviderStrategy")
	is_array(cps)
	count(cps) > 0
	sum([to_number(object.get(x, "Weight", 0)) | some x in cps]) == 0
}
