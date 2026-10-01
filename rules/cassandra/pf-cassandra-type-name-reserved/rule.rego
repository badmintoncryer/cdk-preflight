package cdk_preflight

import rego.v1

# 2026-10-01 に CreateType で拒否を実測した 26 個だけ（list / map / tuple / frozen は受理された）
_pf_casstnr_names := {"ascii", "bigint", "blob", "boolean", "byte", "counter", "date", "decimal", "double", "duration", "float", "inet", "int", "keyspace", "select", "set", "smallint", "table", "text", "time", "timestamp", "timeuuid", "tinyint", "uuid", "varchar", "varint"}

violation contains make_diag_full("pf-cassandra-type-name-reserved", "ERROR", name, "Properties.TypeName",
	sprintf("TypeName %v is a built-in CQL type name or reserved keyword; Keyspaces rejects it", [n]),
	"Rename the type, e.g. my_set",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-type.html#cfn-cassandra-type-typename") if {
	some name in resources_of_type("AWS::Cassandra::Type")
	n := object.get(input.resources[name].properties, "TypeName", null)
	is_string(n)
	n in _pf_casstnr_names
}
