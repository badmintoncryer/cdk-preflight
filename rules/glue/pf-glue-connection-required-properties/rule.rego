package cdk_preflight

import rego.v1

# CreateConnection answers the same generic "Validation for connection properties
# failed" for every one of these, so one rule carries the table. The entries were
# measured one key at a time against CreateConnection (2026-09-14, us-east-1).
_pf_glueconnreq_required := {
	"JDBC": {"JDBC_CONNECTION_URL"},
	"KAFKA": {"KAFKA_BOOTSTRAP_SERVERS"},
	"MONGODB": {"CONNECTION_URL"},
	"CUSTOM": {"CONNECTOR_URL", "CONNECTOR_TYPE", "CONNECTOR_CLASS_NAME"},
	"MARKETPLACE": {"CONNECTOR_URL", "CONNECTOR_TYPE", "CONNECTOR_CLASS_NAME"},
}

violation contains make_diag_full("pf-glue-connection-required-properties", "ERROR", name,
	sprintf("Properties.ConnectionInput.ConnectionProperties.%s", [k]),
	sprintf("A %s connection has no %s in ConnectionProperties; CreateConnection fails with \"Validation for connection properties failed\"", [ct, k]),
	sprintf("Add %s to ConnectionInput.ConnectionProperties", [k]),
	"https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html") if {
	some name in resources_of_type("AWS::Glue::Connection")
	ct := _pf_gluelib_connection_type(name)
	some k in _pf_glueconnreq_required[ct]
	object.get(_pf_gluelib_connection_props(name), k, "__pf_absent") == "__pf_absent"
}
