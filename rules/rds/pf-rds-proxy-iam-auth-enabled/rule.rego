package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-proxy-iam-auth-enabled", "ERROR", name,
	"Properties.Auth",
	sprintf("IAMAuth: ENABLED with EngineFamily %v (\"Unsupported IAM Auth mode ENABLED, need to be in [DISABLED, REQUIRED]\")", [ef]),
	"Use DISABLED or REQUIRED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbproxy.html") if {
	some name in resources_of_type("AWS::RDS::DBProxy")
	ef0 := resolve(name, "Properties.EngineFamily")
	is_string(ef0)
	ef := upper(ef0)
	ef != "SQLSERVER"
	some a in flatten_list(name, "Properties.Auth")
	object.get(a.value, "IAMAuth", "__pf_absent") == "ENABLED"
}
