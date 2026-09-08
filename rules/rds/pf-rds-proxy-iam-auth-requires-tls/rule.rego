package cdk_preflight

import rego.v1

_pf_rdstls_off(name) if not _pf_rds_has(name, "RequireTLS")

_pf_rdstls_off(name) if _pf_rds_false(name, "RequireTLS")

violation contains make_diag_full("pf-rds-proxy-iam-auth-requires-tls", "ERROR", name,
	"Properties.Auth",
	"IAMAuth: REQUIRED without RequireTLS: true (\"Must enable TLS, when IAM Auth is required\")",
	"Set RequireTLS: true, or use IAMAuth: DISABLED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbproxy.html") if {
	some name in resources_of_type("AWS::RDS::DBProxy")
	some a in flatten_list(name, "Properties.Auth")
	object.get(a.value, "IAMAuth", "__pf_absent") == "REQUIRED"
	_pf_rdstls_off(name)
}
