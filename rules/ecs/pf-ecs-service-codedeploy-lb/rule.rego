package cdk_preflight

import rego.v1

# Fires on a missing key or a present-but-empty list; an unresolvable
# LoadBalancers value stays silent (marker objects are "present").
_pf_ecscdlb_none(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "LoadBalancers", "__pf_absent") == "__pf_absent"
}

_pf_ecscdlb_none(name) if {
	props := input.resources[name].properties
	is_object(props)
	lbs := object.get(props, "LoadBalancers", null)
	is_array(lbs)
	count(lbs) == 0
}

violation contains make_diag_full("pf-ecs-service-codedeploy-lb", "ERROR", name,
	"Properties.DeploymentController",
	"DeploymentController is CODE_DEPLOY but no LoadBalancers are configured; CreateService fails with \"the service requires an Application Load Balancer or Network Load Balancer\"",
	"Add a LoadBalancers entry with a target group, or use the ECS controller",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.DeploymentController.Type") == "CODE_DEPLOY"
	_pf_ecscdlb_none(name)
}
