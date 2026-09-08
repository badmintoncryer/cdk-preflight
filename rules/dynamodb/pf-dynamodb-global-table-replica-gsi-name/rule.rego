package cdk_preflight

import rego.v1

_pf_ddbrgi_names(name) := {n |
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	n := object.get(g.value, "IndexName", null)
	is_string(n)
}

# An unresolvable index name anywhere makes the name set incomplete.
_pf_ddbrgi_resolvable(name) if {
	every g in [x | some x in flatten_list(name, "Properties.GlobalSecondaryIndexes")] {
		is_string(object.get(g.value, "IndexName", null))
	}
}

violation contains make_diag_full("pf-dynamodb-global-table-replica-gsi-name", "ERROR", name,
	sprintf("Properties.Replicas.%d.GlobalSecondaryIndexes", [r.index]),
	sprintf("Replica '%s' configures index '%s', which the global table does not declare in GlobalSecondaryIndexes", [region, iname]),
	"Use the same IndexName as the table-level GlobalSecondaryIndexes entry (a replica can only override settings of an existing index)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-replicaglobalsecondaryindexspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddbrgi_resolvable(name)
	some r in flatten_list(name, "Properties.Replicas")
	some g in object.get(r.value, "GlobalSecondaryIndexes", [])
	iname := object.get(g, "IndexName", null)
	is_string(iname)
	not iname in _pf_ddbrgi_names(name)
	region := object.get(r.value, "Region", "<unknown>")
}
