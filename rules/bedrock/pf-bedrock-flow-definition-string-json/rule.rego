package cdk_preflight

import rego.v1

# DefinitionString is an opaque string to the schema; the handler parses it as
# JSON before CreateFlow (measured 2026-09-06). Intrinsics that resolve() cannot
# flatten are skipped.
violation contains make_diag_full("pf-bedrock-flow-definition-string-json", "ERROR", name,
	"Properties.DefinitionString",
	"DefinitionString is not valid JSON; the stack fails with \"Could not parse DefinitionString to valid flow resource definition\"",
	"Provide the flow definition as a JSON document (Nodes / Connections, CloudFormation property names)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-flow.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	s := resolve(name, "Properties.DefinitionString")
	is_string(s)
	not json.is_valid(s)
}
