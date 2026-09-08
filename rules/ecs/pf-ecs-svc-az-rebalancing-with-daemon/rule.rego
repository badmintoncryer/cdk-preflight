package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-az-rebalancing-with-daemon", "ERROR", name,
	"Properties.AvailabilityZoneRebalancing",
	"A DAEMON service enables AvailabilityZoneRebalancing; CreateService fails with \"Availability Zone Rebalancing does not support DAEMON services\"",
	"Drop AvailabilityZoneRebalancing, or use the REPLICA scheduling strategy",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.SchedulingStrategy") == "DAEMON"
	resolve(name, "Properties.AvailabilityZoneRebalancing") == "ENABLED"
}
