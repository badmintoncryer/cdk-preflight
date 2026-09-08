package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-placement-strategies-max6", "ERROR", name,
	"Properties.PlacementStrategies",
	sprintf("The service declares %d placement strategies; CreateService fails with \"Maximum number of strategies is 5\"", [count(ps)]),
	"Reduce PlacementStrategies to 5 entries",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	ps := _pf_ecs_get(name, "PlacementStrategies")
	count(ps) > 5
}
