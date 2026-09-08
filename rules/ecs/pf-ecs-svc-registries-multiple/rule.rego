package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-registries-multiple", "ERROR", name,
	"Properties.ServiceRegistries",
	sprintf("The service declares %d service registries; CreateService fails with \"service registries can have at most 1 items\"", [count(sr)]),
	"Keep a single ServiceRegistries entry",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	sr := _pf_ecs_get(name, "ServiceRegistries")
	count(sr) > 1
}
