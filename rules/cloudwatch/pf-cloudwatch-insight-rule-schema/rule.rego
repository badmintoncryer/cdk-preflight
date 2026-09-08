package cdk_preflight

import rego.v1

_pf_cwirs_ok(obj) if {
	schema := object.get(obj, "Schema", null)
	is_object(schema)
	object.get(schema, "Name", null) == "CloudWatchLogRule"
	object.get(schema, "Version", null) == 1
}

violation contains make_diag_full("pf-cloudwatch-insight-rule-schema", "ERROR", name,
	"Properties.RuleBody",
	"The rule body Schema is not {\"Name\": \"CloudWatchLogRule\", \"Version\": 1}; PutInsightRule fails with \"INVALID_RULE_BODY: InvalidSchema encountered at Schema in the RuleBody.\"",
	"Set Schema to {\"Name\": \"CloudWatchLogRule\", \"Version\": 1}",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContributorInsights-RuleSyntax.html") if {
	some name in resources_of_type("AWS::CloudWatch::InsightRule")
	obj := _pf_cwlib_rulebody(name)
	not _pf_cwirs_ok(obj)
}
