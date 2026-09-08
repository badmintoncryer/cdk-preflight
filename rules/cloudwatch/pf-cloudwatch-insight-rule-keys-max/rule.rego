package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-insight-rule-keys-max", "ERROR", name,
	"Properties.RuleBody",
	sprintf("Contribution.Keys has %d entries; PutInsightRule fails with \"RULE_BODY_COMPLEXITY: A RuleBody must have no more than 4 Keys in the Contribution.\"", [n]),
	"Keep Contribution.Keys to 4 fields",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	keys := object.get(obj, ["Contribution", "Keys"], null)
	is_array(keys)
	n := count(keys)
	n > 4
}
