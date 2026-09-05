package cdk_preflight

import rego.v1

# These properties are oneOf unions in the registry schema. The bundled engine
# reports a two-member object (F3018) but not an empty one; CloudFormation's
# early validation or the resource handler then rejects it. Table: [type, key].
_pf_acunion_table := [
	["AWS::BedrockAgentCore::Evaluator", "EvaluatorConfig"],
	["AWS::BedrockAgentCore::GatewayTarget", "TargetConfiguration"],
	["AWS::BedrockAgentCore::Policy", "Definition"],
]

violation contains make_diag_full("pf-agentcore-required-union-empty", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%s is an empty object; it must hold exactly one member and CloudFormation rejects the template (0 subschemas matched instead of one)", [key]),
	sprintf("Set one member of %s", [key]),
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_EvaluatorConfiguration.html") if {
	some [t, key] in _pf_acunion_table
	some name in resources_of_type(t)
	props := input.resources[name].properties
	is_object(props)
	v := object.get(props, key, null)
	is_object(v)
	count(v) == 0
}
