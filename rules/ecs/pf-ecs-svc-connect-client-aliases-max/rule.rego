package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-connect-client-aliases-max", "ERROR", name,
	"Properties.ServiceConnectConfiguration.Services",
	sprintf("A Service Connect service declares %d client aliases; CreateService fails with \"%d clientAliases exceeds the max limit of 1\"", [count(ca), count(ca)]),
	"Keep a single ClientAliases entry",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	scc := _pf_ecs_get(name, "ServiceConnectConfiguration")
	svcs := _pf_ecs_oget(scc, "Services")
	is_array(svcs)
	some s in svcs
	ca := object.get(s, "ClientAliases", [])
	count(ca) > 1
}
