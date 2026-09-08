package cdk_preflight

import rego.v1

# The path is the patch path of the underlying UpdateStage call: it starts with
# a slash and encodes the resource's own slashes as ~1.
_pf_apgmsrp_ok(p) if {
	startswith(p, "/")
	not contains(substring(p, 1, -1), "/")
}

violation contains make_diag_full("pf-apigw-stage-method-setting-resource-path", "ERROR", name,
	"Properties.MethodSettings",
	sprintf("MethodSettings ResourcePath '%s' is not a method setting path; the stage update fails with \"Invalid method setting path: %s\"", [p, p]),
	"Start the path with / and encode the resource path's slashes as ~1 (e.g. /~1pets), or use /* for every method",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-stage-methodsetting.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	some item in flatten_list(name, "Properties.MethodSettings")
	m := item.value
	is_object(m)
	p := m.ResourcePath
	is_string(p)
	not _pf_apgmsrp_ok(p)
}
