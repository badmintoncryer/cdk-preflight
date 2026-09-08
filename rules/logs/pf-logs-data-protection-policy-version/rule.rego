package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-data-protection-policy-version", "ERROR", name,
	"Properties.DataProtectionPolicy",
	sprintf("The data protection policy Version is '%s'; PutDataProtectionPolicy fails with \"Policy Version must be 2021-06-01\"", [v]),
	"Set Version to 2021-06-01 (this is not an IAM policy document)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-start.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	obj := _pf_lglib_dpp(name)
	v := object.get(obj, "Version", null)
	is_string(v)
	v != "2021-06-01"
}
