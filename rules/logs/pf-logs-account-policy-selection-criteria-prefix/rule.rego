package cdk_preflight

import rego.v1

_pf_lgapp_types := {"FIELD_INDEX_POLICY", "TRANSFORMER_POLICY"}

violation contains make_diag_full("pf-logs-account-policy-selection-criteria-prefix", "ERROR", name,
	"Properties.SelectionCriteria",
	sprintf("A %s selects with LogGroupNamePrefix, but SelectionCriteria is '%s'; PutAccountPolicy fails with \"Invalid selection criteria provided.\"", [policy_type, c]),
	"Use LogGroupNamePrefix \"/my/prefix\"",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	policy_type := resolve(name, "Properties.PolicyType")
	policy_type in _pf_lgapp_types
	c := resolve(name, "Properties.SelectionCriteria")
	is_string(c)
	not regex.match(`(?i)^\s*LogGroupNamePrefix\s`, c)
}
