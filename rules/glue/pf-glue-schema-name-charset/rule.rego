package cdk_preflight

import rego.v1

# Measured against CreateSchema: "." joins the documented set, while a space,
# "@" and "/" are rejected. Names that still carry a ${...} placeholder are a
# template substitution, not a literal, and are left alone.
violation contains make_diag_full("pf-glue-schema-name-charset", "ERROR", name,
	"Properties.Name",
	sprintf("Schema name \"%s\" has a character outside [A-Za-z0-9-_$#.]; CreateSchema fails with \"The parameter value contains one or more characters that are not valid. Parameter Name: schemaName\"", [n]),
	"Use only letters, digits, hyphen, underscore, dollar sign, hash mark or dot in the schema name",
	"https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html") if {
	some name in resources_of_type("AWS::Glue::Schema")
	n := _pf_gluelib_str(name, "Properties.Name")
	not contains(n, "${")
	not regex.match(`^[A-Za-z0-9._$#-]+$`, n)
}
