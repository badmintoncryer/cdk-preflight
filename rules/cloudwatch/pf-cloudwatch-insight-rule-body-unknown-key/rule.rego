package cdk_preflight

import rego.v1

# ponytail: an allowlist over the documented top-level keys. Fields is kept in
# the set because the CLF form documents it there; only keys outside the set
# fire.
_pf_cwirk_keys := {"Schema", "LogGroupNames", "LogFormat", "Contribution", "AggregateOn", "Fields"}

violation contains make_diag_full("pf-cloudwatch-insight-rule-body-unknown-key", "ERROR", name,
	"Properties.RuleBody",
	sprintf("RuleBody has the unknown top-level key '%s'; PutInsightRule fails with \"INVALID_RULE_BODY: UnknownKey encountered at %s in the RuleBody.\"", [key, key]),
	"Filters and the contribution fields belong inside Contribution, not at the top level",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	some key in object.keys(obj)
	not key in _pf_cwirk_keys
}
