package cdk_preflight

import rego.v1

_pf_ecscde_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-taskdefinition.html"

_pf_ecscde_msg := "RegisterTaskDefinition needs at least one container; the service fails with \"Container list cannot be empty\""

_pf_ecscde_fix := "Add at least one entry to ContainerDefinitions"

# The registry schema marks no TaskDefinition property as required, so an
# absent or empty ContainerDefinitions sails through schema validation and
# dies at registration. flatten_list returns an empty list for absent and
# empty alike, so both blocks read the preprocessed document (input.resources)
# to tell a literal empty list from an unresolvable value such as Fn::If.
_pf_ecscde_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

violation contains make_diag_full("pf-ecs-container-definitions-empty", "ERROR", name,
	"Properties",
	_pf_ecscde_msg,
	_pf_ecscde_fix,
	_pf_ecscde_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	props := _pf_ecscde_props(name)
	object.get(props, "ContainerDefinitions", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ecs-container-definitions-empty", "ERROR", name,
	"Properties.ContainerDefinitions",
	_pf_ecscde_msg,
	_pf_ecscde_fix,
	_pf_ecscde_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	props := _pf_ecscde_props(name)
	raw := object.get(props, "ContainerDefinitions", null)
	is_array(raw)
	count(raw) == 0
}
