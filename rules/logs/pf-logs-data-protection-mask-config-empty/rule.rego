package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-data-protection-mask-config-empty", "ERROR", name,
	"Properties.DataProtectionPolicy",
	sprintf("Deidentify MaskConfig carries the field '%s'; PutDataProtectionPolicy fails with \"%s is not a valid field\"", [key, key]),
	"Leave MaskConfig as an empty object - the masking character is not configurable",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-start.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	obj := _pf_lglib_dpp(name)
	stmts := object.get(obj, "Statement", null)
	is_array(stmts)
	some st in stmts
	is_object(st)
	mask := object.get(st, ["Operation", "Deidentify", "MaskConfig"], null)
	is_object(mask)
	some key in object.keys(mask)
}
