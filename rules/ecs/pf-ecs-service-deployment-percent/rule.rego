package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-service-deployment-percent", "ERROR", name,
	"Properties.DeploymentConfiguration.MinimumHealthyPercent",
	sprintf("MinimumHealthyPercent %v exceeds 100; CreateService fails with \"minimumHealthyPercent must be at most 100\"", [minp]),
	"Keep MinimumHealthyPercent at 100 or below",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	minp := to_number(resolve(name, "Properties.DeploymentConfiguration.MinimumHealthyPercent"))
	minp > 100
}

violation contains make_diag_full("pf-ecs-service-deployment-percent", "ERROR", name,
	"Properties.DeploymentConfiguration.MaximumPercent",
	sprintf("MaximumPercent %v is below 100; CreateService fails with \"maximumPercent must be at least 100\"", [maxp]),
	"Keep MaximumPercent at 100 or above",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	maxp := to_number(resolve(name, "Properties.DeploymentConfiguration.MaximumPercent"))
	maxp < 100
}
