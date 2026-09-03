package cdk_preflight

import rego.v1

# DesiredCount 0 fails too (sv03b) - any presence of the key is the violation.
violation contains make_diag_full("pf-ecs-service-daemon-desired-count", "ERROR", name,
	"Properties.DesiredCount",
	"SchedulingStrategy is DAEMON but DesiredCount is set; CreateService fails with \"The daemon scheduling strategy does not support a desired count for services\"",
	"Remove DesiredCount from DAEMON services",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.SchedulingStrategy") == "DAEMON"
	props := input.resources[name].properties
	is_object(props)
	not object.get(props, "DesiredCount", "__pf_absent") == "__pf_absent"
}
