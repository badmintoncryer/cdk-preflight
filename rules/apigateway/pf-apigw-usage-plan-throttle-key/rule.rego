package cdk_preflight

import rego.v1

# The map key is "{resourcePath}/{httpMethod}" - a DSL inside a key.
_pf_apguptk_ok(k) if regex.match(`^/.*/(GET|PUT|POST|DELETE|PATCH|OPTIONS|HEAD|ANY|\*)$`, k)

violation contains make_diag_full("pf-apigw-usage-plan-throttle-key", "ERROR", name,
	"Properties.ApiStages",
	sprintf("Per-method throttle key '%s' is not \"{resourcePath}/{httpMethod}\"; the usage plan create fails with \"Invalid method {resourcePath: %s,method: } specified\"", [k, k]),
	"Use keys like /pets/GET (or //GET for the root resource)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-usageplan-apistage.html") if {
	some name in resources_of_type("AWS::ApiGateway::UsagePlan")
	some item in flatten_list(name, "Properties.ApiStages")
	a := item.value
	is_object(a)
	th := a.Throttle
	is_object(th)
	some k, _ in th
	not _pf_apguptk_ok(k)
}
