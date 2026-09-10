package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-snowflake-role-config", "ERROR", name,
	"Properties.SnowflakeDestinationConfiguration.SnowflakeRoleConfiguration.SnowflakeRole",
	"the Snowflake role configuration is enabled but SnowflakeRole is not set; the stream create fails with \"Must provide SnowflakeRole when SnowflakeRoleConfiguration is enabled.\"",
	"Set SnowflakeRole, or disable SnowflakeRoleConfiguration",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_SnowflakeRoleConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SnowflakeDestinationConfiguration"
	rc := object.get(c, "SnowflakeRoleConfiguration", null)
	is_object(rc)
	coerce_to_bool(object.get(rc, "Enabled", false)) == true
	object.get(rc, "SnowflakeRole", "__pf_absent") == "__pf_absent"
}
