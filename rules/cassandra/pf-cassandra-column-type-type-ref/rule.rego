package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-type-type-ref", "ERROR", name, path,
	sprintf("%v uses a Ref to the AWS::Cassandra::Type %v; that Ref returns keyspace|type, which is not a CQL type (Keyspaces answers with a parse error at the |)", [path, x]),
	"Write the type name as a literal string (e.g. frozen<address>) and add DependsOn on the AWS::Cassandra::Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-type.html#aws-resource-cassandra-type-return-values") if {
	some [name, kind, p, c] in _pf_cass_rawcol
	path := concat(".", [p, _pf_cass_typekey(kind)])
	v := object.get(c, _pf_cass_typekey(kind), null)
	is_object(v)
	some x in resources_of_type("AWS::Cassandra::Type")
	_pf_casstr_refs(v, x)
}

_pf_casstr_refs(v, x) if {
	v.__kind == "resource"
	v.__ref == x
}

_pf_casstr_refs(v, x) if {
	d := v.__dynamic
	is_string(d)
	contains(d, sprintf("${%v}", [x]))
}

_pf_casstr_refs(v, x) if {
	d := v.__dynamic
	is_string(d)
	contains(d, sprintf("{ref:%v}", [x]))
}
