package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-insight-rule-body-json", "ERROR", name,
	"Properties.RuleBody",
	"RuleBody is not valid JSON; PutInsightRule fails with \"INVALID_RULE_BODY: The RuleBody could not be parsed.\"",
	"Render the rule body with JSON.stringify / Fn::ToJsonString instead of hand-written JSON",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	body := resolve(name, "Properties.RuleBody")
	is_string(body)
	not json.is_valid(body)
}
