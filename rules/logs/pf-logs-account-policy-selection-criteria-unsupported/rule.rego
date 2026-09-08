package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-account-policy-selection-criteria-unsupported", "ERROR", name,
	"Properties.SelectionCriteria",
	"A DATA_PROTECTION_POLICY account policy cannot narrow its scope; PutAccountPolicy fails with \"SelectionCriteria is not yet supported for the DATA_PROTECTION_POLICY policy type.\"",
	"Drop SelectionCriteria - a data protection account policy applies to every log group",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAccountPolicy.html") if {
	some name in resources_of_type("AWS::Logs::AccountPolicy")
	resolve(name, "Properties.PolicyType") == "DATA_PROTECTION_POLICY"
	is_string(resolve(name, "Properties.SelectionCriteria"))
}
