package cdk_preflight

import rego.v1

_pf_rdspxauth := {
	"MYSQL": {"MYSQL_NATIVE_PASSWORD", "MYSQL_CACHING_SHA2_PASSWORD"},
	"POSTGRESQL": {"POSTGRES_SCRAM_SHA_256", "POSTGRES_MD5"},
	"SQLSERVER": {"SQL_SERVER_AUTHENTICATION"},
}

violation contains make_diag_full("pf-rds-proxy-client-password-auth-engine", "ERROR", name,
	"Properties.Auth",
	sprintf("ClientPasswordAuthType %v is not valid for EngineFamily %v (\"The client password auth type POSTGRES_SCRAM_SHA_256 that you specified isn't valid. The engine family MYSQL supports only the following types: ...\")", [t, ef]),
	"Use an auth type the engine family supports",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbproxy.html") if {
	some name in resources_of_type("AWS::RDS::DBProxy")
	ef0 := resolve(name, "Properties.EngineFamily")
	is_string(ef0)
	ef := upper(ef0)
	allowed := _pf_rdspxauth[ef]
	some a in flatten_list(name, "Properties.Auth")
	t := object.get(a.value, "ClientPasswordAuthType", "__pf_absent")
	is_string(t)
	t != "__pf_absent"
	not t in allowed
}
