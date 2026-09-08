package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-daemon-with-placement-strategies", "ERROR", name,
	"Properties.PlacementStrategies",
	"A DAEMON service declares placement strategies; CreateService fails with \"The daemon scheduling strategy does not support placement strategies\"",
	"Drop PlacementStrategies from the DAEMON service",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.SchedulingStrategy") == "DAEMON"
	ps := _pf_ecs_get(name, "PlacementStrategies")
	count(ps) > 0
}
