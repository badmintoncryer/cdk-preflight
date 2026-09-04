package cdk_preflight

import rego.v1

_pf_sfndef_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-statemachine.html"

_pf_sfndef_fix := "Keep one of Definition / DefinitionString / DefinitionS3Location"

violation contains make_diag_full("pf-sfn-definition-exactly-one", "ERROR", name,
	"Properties",
	sprintf("%d of Definition / DefinitionString / DefinitionS3Location are set; exactly one is required, and the resource handler fails with \"Property validation failed. Please use one of [DefinitionS3Location], [DefinitionString] or [Definition].\"", [n]),
	_pf_sfndef_fix, _pf_sfndef_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	props := input.resources[name].properties
	is_object(props)
	n := count({k | some k in ["Definition", "DefinitionString", "DefinitionS3Location"]; _pf_sfnlib_has(props, k)})
	n != 1
}
