package cdk_preflight

import rego.v1

# Gray zone: the bundled engine knows this enum but reports it as W3030 (WARN), which
# blocks nothing. Retires with the upstream severity fix (meta upstream: pending-engine).
_pf_rsslog_allowed := {"useractivitylog", "userlog", "connectionlog"}

violation contains make_diag_full("pf-redshiftserverless-log-exports-enum", "ERROR", name,
	"Properties.LogExports",
	sprintf("LogExports contains %v, which is not one of useractivitylog / userlog / connectionlog; CreateNamespace fails with \"Value '[querylog]' at 'logExports' failed to satisfy constraint: Member must satisfy enum value set: [connectionlog, useractivitylog, userlog]\"", [v]),
	"Use only useractivitylog, userlog and connectionlog",
	"https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateNamespace.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Namespace")
	some it in flatten_list(name, "Properties.LogExports")
	v := it.value
	is_string(v)
	not v in _pf_rsslog_allowed
}
