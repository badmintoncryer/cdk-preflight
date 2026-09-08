package cdk_preflight

import rego.v1

# The offset ceiling is a function of the period (the doc's combination table).
_pf_apgupqo_max("DAY") := 0

_pf_apgupqo_max("WEEK") := 6

_pf_apgupqo_max("MONTH") := 27

violation contains make_diag_full("pf-apigw-usage-plan-quota-offset-range", "ERROR", name,
	"Properties.Quota.Offset",
	sprintf("Quota.Offset %v is out of range for period %s (0-%d); the usage plan create fails with \"Usage Plan quota offset must be between 0 and %d inclusive in the %s period\"", [off, period, mx, mx, period]),
	sprintf("Use an offset between 0 and %d for the %s period", [mx, period]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-usageplan-quotasettings.html") if {
	some name in resources_of_type("AWS::ApiGateway::UsagePlan")
	period := resolve(name, "Properties.Quota.Period")
	mx := _pf_apgupqo_max(period)
	off := to_number(resolve(name, "Properties.Quota.Offset"))
	off > mx
}
