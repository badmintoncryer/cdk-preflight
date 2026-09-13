package cdk_preflight

import rego.v1

# A SNOWFLAKE connection carries its compute-environment settings as JSON
# strings under ConnectionProperties (the top-level SparkProperties /
# PythonProperties members of CreateConnection are ignored by the validator,
# measured 2026-09-14). Only a literal, parseable object is inspected, so a
# token or a malformed string is left to other layers.
#
# The service pattern is unanchored: a port, a path or a further suffix after
# the host is accepted (measured 2026-09-14), so this one is matched verbatim
# without ^ or $.
_pf_gluesfurl_spark(name) := o if {
	raw := object.get(_pf_gluelib_connection_props(name), "SparkProperties", null)
	is_string(raw)
	not input.resources[raw]
	json.is_valid(raw)
	o := json.unmarshal(raw)
	is_object(o)
}

_pf_gluesfurl_bad(o) := u if {
	u := object.get(o, "sfUrl", null)
	is_string(u)
	not regex.match(`.+[.]snowflakecomputing[.](com|cn)`, u)
}

violation contains make_diag_full("pf-glue-connection-snowflake-spark-url", "ERROR", name,
	"Properties.ConnectionInput.ConnectionProperties.SparkProperties",
	sprintf("the SNOWFLAKE connection's sfUrl \"%s\" is not a Snowflake account URL; CreateConnection fails with \"SparkProperties.sfUrl: does not match the regex pattern .+[.]snowflakecomputing[.](com|cn)\"", [_pf_gluesfurl_bad(_pf_gluesfurl_spark(name))]),
	"Set sfUrl to the Snowflake account URL, which ends in .snowflakecomputing.com or .snowflakecomputing.cn",
	"https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html") if {
	some name in resources_of_type("AWS::Glue::Connection")
	_pf_gluelib_connection_type(name) == "SNOWFLAKE"
	_pf_gluesfurl_bad(_pf_gluesfurl_spark(name))
}
