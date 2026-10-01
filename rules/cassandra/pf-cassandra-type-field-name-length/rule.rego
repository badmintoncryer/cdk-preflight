package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-type-field-name-length", "ERROR", name, sprintf("Properties.Fields.%d.FieldName", [i]),
	sprintf("FieldName is %d characters; Keyspaces allows at most 128", [count(n)]),
	"Shorten the field name to 128 characters or fewer",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/quotas.html#quotas-udts") if {
	some name in resources_of_type("AWS::Cassandra::Type")
	fs := object.get(input.resources[name].properties, "Fields", null)
	is_array(fs)
	some i, f in fs
	is_object(f)
	n := object.get(f, "FieldName", null)
	is_string(n)
	count(n) > 128
}
