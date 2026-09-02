package cdk_preflight

import rego.v1

# Valid forms per the service error itself: plain [a-zA-Z0-9._:-]+, or a
# whole-part variable {name} / greedy {name+}.
_pf_apgrpp_ok(pp) if regex.match(`^[a-zA-Z0-9._:-]+$`, pp)

_pf_apgrpp_ok(pp) if regex.match(`^\{[a-zA-Z0-9._-]+\+?\}$`, pp)

violation contains make_diag_full("pf-apigw-resource-path-part", "ERROR", name,
	"Properties.PathPart",
	sprintf("PathPart '%s' has characters the service rejects; the resource create fails with \"Resource's path part only allow a-zA-Z0-9._-: or a valid greedy path variable and curly braces at the beginning and the end.\"", [pp]),
	"Use only a-zA-Z0-9._-: in the path part, or a single {variable} / {greedy+} form",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-resource.html") if {
	some name in resources_of_type("AWS::ApiGateway::Resource")
	pp := resolve(name, "Properties.PathPart")
	is_string(pp)
	not _pf_apgrpp_ok(pp)
}
