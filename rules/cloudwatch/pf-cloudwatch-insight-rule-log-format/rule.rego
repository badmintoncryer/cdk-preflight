package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-insight-rule-log-format", "ERROR", name,
	"Properties.RuleBody",
	sprintf("LogFormat '%s' is not JSON or CLF; PutInsightRule fails with \"INVALID_RULE_BODY: InvalidValueType encountered at LogFormat in the RuleBody.\"", [f]),
	"Set LogFormat to JSON or CLF",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	f := object.get(obj, "LogFormat", null)
	is_string(f)
	not f in {"JSON", "CLF"}
}
