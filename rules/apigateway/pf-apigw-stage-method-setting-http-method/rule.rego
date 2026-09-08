package cdk_preflight

import rego.v1

_pf_apgmshm_verbs := {"GET", "PUT", "POST", "DELETE", "PATCH", "OPTIONS", "HEAD", "ANY", "*"}

violation contains make_diag_full("pf-apigw-stage-method-setting-http-method", "ERROR", name,
	"Properties.MethodSettings",
	sprintf("MethodSettings HttpMethod '%s' is not an API Gateway method; the stage update fails with \"Invalid method setting path\"", [m]),
	"Use one of GET PUT POST DELETE PATCH OPTIONS HEAD ANY, or * for every method",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-stage-methodsetting.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	some item in flatten_list(name, "Properties.MethodSettings")
	s := item.value
	is_object(s)
	m := s.HttpMethod
	is_string(m)
	not m in _pf_apgmshm_verbs
}
