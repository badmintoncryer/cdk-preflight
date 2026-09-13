package cdk_preflight

import rego.v1

# USERNAME alone and PASSWORD alone are both rejected; SECRET_ID on its own is
# accepted. ENCRYPTED_PASSWORD stands in for PASSWORD so accounts with catalog
# encryption turned on are never flagged.
_pf_glueconncred_has(cp, k) if {
	object.get(cp, k, "__pf_absent") != "__pf_absent"
}

_pf_glueconncred_ok(cp) if _pf_glueconncred_has(cp, "SECRET_ID")

_pf_glueconncred_ok(cp) if {
	_pf_glueconncred_has(cp, "USERNAME")
	_pf_glueconncred_has(cp, "PASSWORD")
}

_pf_glueconncred_ok(cp) if {
	_pf_glueconncred_has(cp, "USERNAME")
	_pf_glueconncred_has(cp, "ENCRYPTED_PASSWORD")
}

violation contains make_diag_full("pf-glue-connection-jdbc-credentials", "ERROR", name,
	"Properties.ConnectionInput.ConnectionProperties",
	"A JDBC connection carries neither USERNAME with PASSWORD nor SECRET_ID; CreateConnection fails with \"Validation for connection properties failed\"",
	"Set both USERNAME and PASSWORD, or point SECRET_ID at a Secrets Manager secret in the same region",
	"https://docs.aws.amazon.com/glue/latest/dg/connection-properties.html") if {
	some name in resources_of_type("AWS::Glue::Connection")
	_pf_gluelib_connection_type(name) == "JDBC"
	cp := _pf_gluelib_connection_props(name)
	not _pf_glueconncred_ok(cp)
}
