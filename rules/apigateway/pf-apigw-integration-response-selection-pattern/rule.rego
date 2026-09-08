package cdk_preflight

import rego.v1

# Only unbalanced brackets are judged: that is the shape the service rejects
# outright, and it cannot be mistaken for a legal pattern.
_pf_apgirsp_unbalanced(p) if count(split(p, "[")) != count(split(p, "]"))

_pf_apgirsp_unbalanced(p) if count(split(p, "(")) != count(split(p, ")"))

violation contains make_diag_full("pf-apigw-integration-response-selection-pattern", "ERROR", name,
	"Properties.Integration.IntegrationResponses",
	sprintf("SelectionPattern '%s' has unbalanced brackets and is not a valid regular expression; the method create fails with \"Invalid regex pattern specified\"", [p]),
	"Write SelectionPattern as a valid regular expression (e.g. \".*Not Found.*\")",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integrationresponse.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	some item in flatten_list(name, "Properties.Integration.IntegrationResponses")
	r := item.value
	is_object(r)
	p := r.SelectionPattern
	is_string(p)
	_pf_apgirsp_unbalanced(p)
}
