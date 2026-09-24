package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-code-handler-blueprint-exclusive", "ERROR", name,
	"Properties.Code.Handler",
	"Code.Handler and Code.BlueprintTypes are both set; a blueprint brings its own entry point, so CreateCanary answers \"Request should contain only either a handler or blueprint types.\"",
	"Drop Handler when the canary is built from BlueprintTypes, or drop BlueprintTypes and keep the handler",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-code.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	_pf_synlib_present(name, ["Code", "Handler"])
	_pf_synlib_present(name, ["Code", "BlueprintTypes"])
}
