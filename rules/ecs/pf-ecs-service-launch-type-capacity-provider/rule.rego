package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-launch-type-capacity-provider", "ERROR", name,
	"Properties.CapacityProviderStrategy",
	sprintf("LaunchType '%s' and CapacityProviderStrategy cannot both be set; CreateService fails with \"Specifying both a launch type and capacity provider strategy is not supported\"", [lt]),
	"Remove LaunchType or the capacity provider strategy",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	lt := resolve(name, "Properties.LaunchType")
	is_string(lt)
	count([q | some q in flatten_list(name, "Properties.CapacityProviderStrategy")]) > 0
}
