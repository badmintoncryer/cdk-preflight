package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-external-with-load-balancers", "ERROR", name,
	"Properties.LoadBalancers",
	"The service uses the EXTERNAL deployment controller but still sets LoadBalancers; CreateService fails with \"LoadBalancers must be empty or null\"",
	"Move the load balancer configuration to the task set",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.DeploymentController.Type") == "EXTERNAL"
	lbs := _pf_ecs_get(name, "LoadBalancers")
	count(lbs) > 0
}
