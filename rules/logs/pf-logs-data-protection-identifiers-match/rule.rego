package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-data-protection-identifiers-match", "ERROR", name,
	"Properties.DataProtectionPolicy",
	"The two statements list different DataIdentifier sets; PutDataProtectionPolicy fails with \"Audit Statement and Deidentify Statement must have the same Data Identifiers\"",
	"Use the same DataIdentifier list in the Audit and the Deidentify statement",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-start.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	obj := _pf_lglib_dpp(name)
	stmts := object.get(obj, "Statement", null)
	is_array(stmts)
	count(stmts) == 2
	first := object.get(stmts[0], "DataIdentifier", null)
	second := object.get(stmts[1], "DataIdentifier", null)
	is_array(first)
	is_array(second)
	sort(first) != sort(second)
}
