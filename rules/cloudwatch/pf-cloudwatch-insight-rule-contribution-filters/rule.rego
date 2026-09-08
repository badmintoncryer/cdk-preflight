package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-insight-rule-contribution-filters", "ERROR", name,
	"Properties.RuleBody",
	"Contribution has no Filters key; PutInsightRule fails with \"INVALID_RULE_BODY: MissingKey encountered at Filters in the RuleBody.\"",
	"Add \"Filters\": [] inside Contribution (an empty list matches every log event)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	contribution := object.get(obj, "Contribution", null)
	is_object(contribution)
	object.get(contribution, "Filters", "__pf_absent") == "__pf_absent"
}
