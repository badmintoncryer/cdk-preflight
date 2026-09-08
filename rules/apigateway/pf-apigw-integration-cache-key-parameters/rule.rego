package cdk_preflight

import rego.v1

# A cache key parameter names a method request parameter, so the two properties
# have to agree inside the same Method resource.
_pf_apgickp_declared(name, c) if {
	rp := resolve(name, "Properties.RequestParameters")
	is_object(rp)
	some k, _ in rp
	k == c
}

violation contains make_diag_full("pf-apigw-integration-cache-key-parameters", "ERROR", name,
	"Properties.Integration.CacheKeyParameters",
	sprintf("Cache key parameter '%s' is not declared in the method's RequestParameters; the method create fails with \"Invalid cache key parameter specified\"", [c]),
	sprintf("Add \"%s\": true to Properties.RequestParameters, or drop it from CacheKeyParameters", [c]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	some item in flatten_list(name, "Properties.Integration.CacheKeyParameters")
	c := item.value
	is_string(c)
	not _pf_apgickp_declared(name, c)
}
