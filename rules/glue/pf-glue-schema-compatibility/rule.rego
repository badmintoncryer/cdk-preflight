package cdk_preflight

import rego.v1

_pf_glueschcompat_valid := {
	"NONE", "DISABLED", "BACKWARD", "BACKWARD_ALL",
	"FORWARD", "FORWARD_ALL", "FULL", "FULL_ALL",
}

violation contains make_diag_full("pf-glue-schema-compatibility", "ERROR", name,
	"Properties.Compatibility",
	sprintf("Compatibility \"%s\" is not a compatibility mode; CreateSchema fails with \"Compatibility is not valid.\"", [c]),
	"Use NONE, DISABLED, BACKWARD, BACKWARD_ALL, FORWARD, FORWARD_ALL, FULL or FULL_ALL",
	"https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html") if {
	some name in resources_of_type("AWS::Glue::Schema")
	c := _pf_gluelib_str(name, "Properties.Compatibility")
	not c in _pf_glueschcompat_valid
}
