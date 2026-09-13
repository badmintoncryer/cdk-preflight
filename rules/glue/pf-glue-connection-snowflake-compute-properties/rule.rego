package cdk_preflight

import rego.v1

# A SNOWFLAKE connection carries its settings as JSON strings under
# ConnectionProperties, keyed by compute environment. Measured against
# CreateConnection 2026-09-14: either key on its own is accepted and the
# plain keys the other connection types use (HOST, ...) are not - nor is
# AthenaProperties, which comes back as "Invalid properties found".
_pf_gluesfcomp_any(cp) if {
	some k in ["SparkProperties", "PythonProperties"]
	object.get(cp, k, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-glue-connection-snowflake-compute-properties", "ERROR", name,
	"Properties.ConnectionInput.ConnectionProperties",
	"the SNOWFLAKE connection has no SparkProperties or PythonProperties in ConnectionProperties; CreateConnection fails with \"PythonProperties: is missing but it is required, SparkProperties: is missing but it is required\"",
	"Add SparkProperties (sfUrl and secretId) or PythonProperties (account) to ConnectionInput.ConnectionProperties as a JSON string",
	"https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html") if {
	some name in resources_of_type("AWS::Glue::Connection")
	_pf_gluelib_connection_type(name) == "SNOWFLAKE"
	not _pf_gluesfcomp_any(_pf_gluelib_connection_props(name))
}
