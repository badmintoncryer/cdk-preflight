package cdk_preflight

import rego.v1

# The three definition carriers are all optional in the schema (no oneOf);
# the CloudFormation handler rejects more than one (measured 2026-09-06).
_pf_fdsrc_keys := ["Definition", "DefinitionString", "DefinitionS3Location"]

violation contains make_diag_full("pf-bedrock-flow-definition-source", "ERROR", name,
	"Properties.Definition",
	sprintf("%d of Definition / DefinitionString / DefinitionS3Location are set; the stack fails with \"you can only specify one of Definition, DefinitionString or DefinitionS3Location\"", [n]),
	"Keep exactly one definition carrier",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-flow.html") if {
	some name in resources_of_type("AWS::Bedrock::Flow")
	p := _pf_bedrocklib_props(name)
	n := count([k | some k in _pf_fdsrc_keys; _pf_bedrocklib_has(p, k)])
	n > 1
}
