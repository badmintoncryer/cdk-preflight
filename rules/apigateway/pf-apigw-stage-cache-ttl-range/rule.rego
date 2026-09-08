package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-stage-cache-ttl-range", "ERROR", name,
	"Properties.MethodSettings",
	sprintf("MethodSettings CacheTtlInSeconds %v is over the cap; the stage update fails with \"Invalid time-to-live setting, must be an integer no greater than 3600\"", [ttl]),
	"Use a cache TTL between 0 and 3600 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-stage-methodsetting.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	some item in flatten_list(name, "Properties.MethodSettings")
	m := item.value
	is_object(m)
	ttl := to_number(m.CacheTtlInSeconds)
	ttl > 3600
}
