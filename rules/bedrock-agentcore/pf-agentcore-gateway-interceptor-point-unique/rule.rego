package cdk_preflight

import rego.v1

# The schema caps InterceptorConfigurations at 2 (F3032) but says nothing about
# which interception point each one binds; CreateGateway rejects a point that is
# bound twice — in one interceptor or across two — with "Only one interceptor
# configuration per interception point can be defined".
_pf_gwicpt_points(name) := [[c.index, p] |
	some c in flatten_list(name, "Properties.InterceptorConfigurations")
	pts := object.get(c.value, "InterceptionPoints", [])
	is_array(pts)
	some p in pts
	is_string(p)
]

violation contains make_diag_full("pf-agentcore-gateway-interceptor-point-unique", "ERROR", name,
	"Properties.InterceptorConfigurations",
	sprintf("Interception point '%s' is bound by more than one interceptor configuration; CreateGateway fails with \"Only one interceptor configuration per interception point can be defined\"", [p]),
	"Bind each interception point (REQUEST, RESPONSE) to exactly one interceptor",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_GatewayInterceptorConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Gateway")
	all := _pf_gwicpt_points(name)
	some [_, p] in all
	count([1 | some [_, q] in all; q == p]) > 1
}
