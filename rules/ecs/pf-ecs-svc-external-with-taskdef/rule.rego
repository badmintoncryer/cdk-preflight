package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-external-with-taskdef", "ERROR", name,
	"Properties.TaskDefinition",
	"The service uses the EXTERNAL deployment controller but still sets TaskDefinition; CreateService fails with \"TaskDefinition must be blank\"",
	"Drop TaskDefinition; task sets carry it for EXTERNAL services",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	resolve(name, "Properties.DeploymentController.Type") == "EXTERNAL"
	_pf_ecs_has(name, "TaskDefinition")
}
