package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-account-policy-selection-criteria-subscription", "ERROR", name,
	"Properties.SelectionCriteria",
	sprintf("SelectionCriteria '%s' is not a LogGroupName NOT IN [...] expression; PutAccountPolicy fails with \"The provided SelectionCriteria string is invalid.\"", [c]),
	"Use LogGroupName NOT IN [\"/aws/lambda/fn\"] - a subscription account policy can only exclude log groups",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	resolve(name, "Properties.PolicyType") == "SUBSCRIPTION_FILTER_POLICY"
	c := resolve(name, "Properties.SelectionCriteria")
	is_string(c)
	not regex.match(`(?i)^\s*LogGroupName\s+NOT\s+IN\s*\[`, c)
}
