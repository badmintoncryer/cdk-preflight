package cdk_preflight

import rego.v1

_pf_fnvtlrequiresfunctionversion_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-fn-vtl-requires-function-version", "ERROR", name,
	"Properties.FunctionVersion",
	"the function uses VTL mapping templates but FunctionVersion is not set; the function create fails because a VTL function is versioned",
	"Set FunctionVersion: 2018-05-29, or use Code with an APPSYNC_JS Runtime",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	is_string(resolve(name, "Properties.RequestMappingTemplate"))
	_pf_fnvtlrequiresfunctionversion_absent(name, "Runtime")
	_pf_fnvtlrequiresfunctionversion_absent(name, "FunctionVersion")
}
