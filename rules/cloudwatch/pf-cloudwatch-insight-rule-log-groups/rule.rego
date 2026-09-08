package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-insight-rule-log-groups", "ERROR", name,
	"Properties.RuleBody",
	"LogGroupNames is empty; PutInsightRule fails with \"INVALID_RULE_BODY: Empty encountered at LogGroupNames in the RuleBody.\"",
	"List at least one log group name (a trailing * is allowed as a prefix match)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	groups := object.get(obj, "LogGroupNames", null)
	is_array(groups)
	count(groups) == 0
}
