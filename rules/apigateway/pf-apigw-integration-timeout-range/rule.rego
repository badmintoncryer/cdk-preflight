package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-integration-timeout-range", "ERROR", name,
	"Properties.Integration.TimeoutInMillis",
	sprintf("Integration.TimeoutInMillis %v is outside 50-29000; the method create fails with \"Timeout should be between 50 ms and 29000 ms\"", [t]),
	"Use an integration timeout between 50 and 29000 milliseconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	t := to_number(resolve(name, "Properties.Integration.TimeoutInMillis"))
	_pf_apgitr_bad(t)
}

_pf_apgitr_bad(t) if t < 50

_pf_apgitr_bad(t) if t > 29000
