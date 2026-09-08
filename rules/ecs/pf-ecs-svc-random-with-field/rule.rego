package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-random-with-field", "ERROR", name,
	"Properties.PlacementStrategies",
	"A random placement strategy carries a Field; CreateService fails with \"random field should not be specified\"",
	"Drop Field from the random strategy",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some ps in flatten_list(name, "Properties.PlacementStrategies")
	object.get(ps.value, "Type", null) == "random"
	_pf_ecs_ohas(ps.value, "Field")
}
