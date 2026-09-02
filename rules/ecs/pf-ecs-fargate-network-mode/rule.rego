package cdk_preflight

import rego.v1

_pf_ecsnm_url := "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#network_mode"

# resolve() cannot tell "absent" from "unresolvable" (both undefined), so true
# absence is proven against the preprocessed document; a Ref-valued NetworkMode
# no longer trips the not-set block.
_pf_ecsnm_absent(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "NetworkMode", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ecs-fargate-network-mode", "ERROR", name,
	"Properties.NetworkMode",
	sprintf("NetworkMode is '%s' but task definitions requiring FARGATE compatibility must use 'awsvpc'; RegisterTaskDefinition fails at deploy time", [nm]),
	"Set NetworkMode to 'awsvpc'",
	_pf_ecsnm_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	rc := resolve(name, "Properties.RequiresCompatibilities")
	is_array(rc)
	"FARGATE" in rc
	nm := resolve(name, "Properties.NetworkMode")
	is_string(nm)
	nm != "awsvpc"
}

# NetworkMode 未指定でも RegisterTaskDefinition は
# "Fargate only supports network mode 'awsvpc'." で失敗する（2026-09-01 実 API 確認）
violation contains make_diag_full("pf-ecs-fargate-network-mode", "ERROR", name,
	"Properties.NetworkMode",
	"NetworkMode is not set, but task definitions requiring FARGATE compatibility must set it to 'awsvpc'; RegisterTaskDefinition fails at deploy time",
	"Set NetworkMode to 'awsvpc'",
	_pf_ecsnm_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	rc := resolve(name, "Properties.RequiresCompatibilities")
	is_array(rc)
	"FARGATE" in rc
	_pf_ecsnm_absent(name)
}
