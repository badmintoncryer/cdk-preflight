package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-classic-lb-with-fargate", "ERROR", name,
	"Properties.LoadBalancers",
	"The service runs on FARGATE but attaches a Classic Load Balancer through LoadBalancerName; CreateService fails with \"Classic Load Balancers are not supported with Fargate\"",
	"Use an Application or Network Load Balancer target group",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	lbs := _pf_ecs_get(name, "LoadBalancers")
	is_array(lbs)
	some lb in lbs
	_pf_ecs_ohas(lb, "LoadBalancerName")
	resolve(name, "Properties.LaunchType") == "FARGATE"
}
