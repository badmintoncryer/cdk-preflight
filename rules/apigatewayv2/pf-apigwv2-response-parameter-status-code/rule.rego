package cdk_preflight

import rego.v1

# The outer key of ResponseParameters selects the status code to rewrite (the
# CloudFormation shape is {"<status>": {"ResponseParameters": [...]}}).
_pf_agvrpsc_bad(k) if {
	regex.match(`^[0-9]+$`, k)
	to_number(k) < 200
}

_pf_agvrpsc_bad(k) if {
	regex.match(`^[0-9]+$`, k)
	to_number(k) > 599
}

violation contains make_diag_full("pf-apigwv2-response-parameter-status-code", "ERROR", name,
	"Properties.ResponseParameters",
	sprintf("ResponseParameters is keyed by status code '%s'; the integration create fails with \"Status Code %s is not valid\"", [k, k]),
	"Key ResponseParameters by a status code between 200 and 599",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	rp := resolve(name, "Properties.ResponseParameters")
	is_object(rp)
	some k, _ in rp
	_pf_agvrpsc_bad(k)
}
