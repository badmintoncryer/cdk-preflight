package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-data-protection-policy-statements", "ERROR", name,
	"Properties.DataProtectionPolicy",
	sprintf("The data protection policy has %d statements; PutDataProtectionPolicy fails with \"Policy can only have two statements. One for Audit Operation and one for Deidentify Operation\"", [n]),
	"Write one Audit statement and one Deidentify statement",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-start.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	obj := _pf_lglib_dpp(name)
	stmts := object.get(obj, "Statement", null)
	is_array(stmts)
	n := count(stmts)
	n != 2
}
