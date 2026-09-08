package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-svc-ebs-name-not-in-taskdef", "ERROR", name,
	"Properties.VolumeConfigurations",
	sprintf("The service configures the volume '%s', which the referenced task definition does not declare; CreateService fails with \"The volume name '%s' in your request does not have a matching volume in your Task Definition\"", [vn, vn]),
	"Declare the volume in the task definition with ConfiguredAtLaunch true",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	some v in flatten_list(name, "Properties.VolumeConfigurations")
	vn := object.get(v.value, "Name", null)
	_pf_ecs_lit(vn)
	td := _pf_ecs_reftd(name, "Properties.TaskDefinition")
	not vn in _pf_ecs_volnames(td)
}
