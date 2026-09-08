package cdk_preflight

import rego.v1

# The key is a mapping expression, not a name: schema types it as a plain
# string map.
_pf_apgmrpk_ok(k) if regex.match(`^method\.request\.(querystring|path|header|multivaluequerystring|multivalueheader)\.[^ ]+$`, k)

violation contains make_diag_full("pf-apigw-method-request-parameter-key", "ERROR", name,
	sprintf("Properties.RequestParameters.%s", [k]),
	sprintf("RequestParameters key '%s' is not a method request mapping expression; the method create fails with \"Invalid mapping expression parameter specified: %s\"", [k, k]),
	"Use method.request.querystring.<name>, method.request.path.<name> or method.request.header.<name>",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-method.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	rp := resolve(name, "Properties.RequestParameters")
	is_object(rp)
	some k, _ in rp
	not _pf_apgmrpk_ok(k)
}
