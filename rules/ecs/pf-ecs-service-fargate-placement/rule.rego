package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-fargate-placement", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%s is set but the FARGATE launch type does not support task placement; CreateService fails at deploy time", [key]),
	"Remove placement constraints/strategies from Fargate services",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.LaunchType") == "FARGATE"
	some key in {"PlacementConstraints", "PlacementStrategies"}
	count([q | some q in flatten_list(name, sprintf("Properties.%s", [key]))]) > 0
}
