package cdk_preflight

import rego.v1

# The service rejects a strategy where more than one entry has Base above zero
# (meta.yaml#repro.expect). An explicit Base: 0, common in CDK code, does not
# count (issue #394).

violation contains make_diag_full("pf-ecs-svc-capacity-provider-multiple-base", "ERROR", name,
	"Properties.CapacityProviderStrategy",
	"More than one capacity provider in the strategy sets Base above zero; CreateService fails with \"There are multiple capacity providers in the specified capacity provider strategy with a base value greater than zero\"",
	"Keep Base above zero on a single capacity provider",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	cps := _pf_ecs_get(name, "CapacityProviderStrategy")
	is_array(cps)
	count([x | some x in cps; _pf_tonum(_pf_ecs_oget(x, "Base")) > 0]) > 1
}
