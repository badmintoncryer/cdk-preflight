package cdk_preflight

import rego.v1

_pf_apgmhv_verbs := {"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY"}

violation contains make_diag_full("pf-apigw-method-http-verb", "ERROR", name,
	"Properties.HttpMethod",
	sprintf("HttpMethod '%s' is not an API Gateway method; the method create fails with \"Invalid HttpMethod specified. Valid options are GET,PUT,POST,DELETE,PATCH,OPTIONS,HEAD,ANY\"", [m]),
	"Use one of GET PUT POST DELETE PATCH OPTIONS HEAD ANY",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	m := resolve(name, "Properties.HttpMethod")
	is_string(m)
	not input.resources[m]
	not m in _pf_apgmhv_verbs
}
