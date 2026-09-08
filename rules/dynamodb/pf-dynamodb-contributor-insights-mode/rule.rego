package cdk_preflight

import rego.v1

# W3030/WARN in the bundled engine (1.7.0-beta) — does not block the deploy.
violation contains make_diag_full("pf-dynamodb-contributor-insights-mode", "ERROR", name,
	"Properties.ContributorInsightsSpecification.Mode",
	sprintf("Contributor Insights Mode '%s' does not exist; UpdateContributorInsights fails with \"Value '%s' at 'contributorInsightsMode' failed to satisfy constraint\"", [m, m]),
	"Use ACCESSED_AND_THROTTLED_KEYS or THROTTLED_KEYS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-contributorinsightsspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	m := resolve(name, "Properties.ContributorInsightsSpecification.Mode")
	is_string(m)
	not m in {"ACCESSED_AND_THROTTLED_KEYS", "THROTTLED_KEYS"}
}
