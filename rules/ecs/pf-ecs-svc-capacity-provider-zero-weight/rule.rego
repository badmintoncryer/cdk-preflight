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
	every x in cps {
		_pf_ecs_czw_known(x)
	}
	sum([_pf_tonum(_pf_oval(x, "Weight")) | some x in cps]) == 0
}

# Weight が書かれていて数値として読めない（参照など）なら、0 かどうか分からない。
_pf_ecs_czw_known(x) if object.get(x, "Weight", "__pf_absent") == "__pf_absent"

_pf_ecs_czw_known(x) if {
	_ := _pf_tonum(x.Weight)
}
