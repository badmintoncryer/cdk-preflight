package cdk_preflight

import rego.v1

_pf_fncodeandmappingtemplateexclusive_vtl(n) if is_string(resolve(n, "Properties.RequestMappingTemplate"))

_pf_fncodeandmappingtemplateexclusive_vtl(n) if is_string(resolve(n, "Properties.ResponseMappingTemplate"))

violation contains make_diag_full("pf-appsync-fn-code-and-mapping-template-exclusive", "ERROR", name,
	"Properties.RequestMappingTemplate",
	"both Code and a VTL mapping template are set; the function create rejects a handler written twice",
	"Keep either Code (APPSYNC_JS) or the VTL mapping templates",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	is_string(resolve(name, "Properties.Code"))
	_pf_fncodeandmappingtemplateexclusive_vtl(name)
}
