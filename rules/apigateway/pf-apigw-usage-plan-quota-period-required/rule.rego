package cdk_preflight

import rego.v1

_pf_apgupqp_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	q := object.get(props, "Quota", {})
	is_object(q)
	object.get(q, "Period", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-usage-plan-quota-period-required", "ERROR", name,
	"Properties.Quota.Period",
	"Quota is set but Quota.Period is not; the usage plan create fails with \"Invalid Usage Plan quota period specified. Must be one of [DAY, WEEK, MONTH]\"",
	"Set Quota.Period to DAY, WEEK or MONTH",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-usageplan-quotasettings.html") if {
	some name in resources_of_type("AWS::ApiGateway::UsagePlan")
	is_object(resolve(name, "Properties.Quota"))
	_pf_apgupqp_missing(name)
}
