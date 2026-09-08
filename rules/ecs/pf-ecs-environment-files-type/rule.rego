package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-environment-files-type", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.EnvironmentFiles", [c.index]),
	sprintf("Container '%s' loads the environment file '%s', which is not an ARN; RegisterTaskDefinition fails with \"Invalid arn syntax\"", [_pf_ecs_cname(c), v]),
	"Give EnvironmentFiles.Value the full arn:<partition>:s3:::<bucket>/<key> form",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	efs := _pf_ecs_cget(c, "EnvironmentFiles")
	is_array(efs)
	some ef in efs
	v := object.get(ef, "Value", null)
	_pf_ecs_lit(v)
	not startswith(v, "arn:")
}
