package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-circuit-breaker-with-code-deploy", "ERROR", name,
	"Properties.DeploymentConfiguration.DeploymentCircuitBreaker",
	sprintf("The service combines the %s deployment controller with a DeploymentCircuitBreaker, which only the ECS controller supports; CreateService fails", [t]),
	"Drop DeploymentCircuitBreaker, or use the ECS deployment controller",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	t := resolve(name, "Properties.DeploymentController.Type")
	t != "ECS"
	_pf_ecs_ohas(_pf_ecs_get(name, "DeploymentConfiguration"), "DeploymentCircuitBreaker")
}
