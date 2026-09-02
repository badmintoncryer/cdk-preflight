package cdk_preflight

import rego.v1

_pf_ddblsh_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-localsecondaryindex.html"

_pf_ddblsh_keytypes(ks) := {kt |
	some k in ks
	kt := object.get(k, "KeyType", null)
	is_string(kt)
}

# Only judge a key schema whose KeyTypes are all literal strings.
_pf_ddblsh_resolvable(ks) if count(_pf_ddblsh_keytypes(ks)) > 0

_pf_ddblsh_resolvable_all(ks) if {
	every k in ks {
		is_string(object.get(k, "KeyType", null))
	}
}

violation contains make_diag_full("pf-dynamodb-lsi-shape", "ERROR", name,
	sprintf("Properties.LocalSecondaryIndexes.%d.KeySchema", [l.index]),
	sprintf("Local secondary index '%s' has no RANGE key; CreateTable fails with \"Index KeySchema does not have a range key for index\"", [iname]),
	"Give the LSI a sort key: [table HASH key, its own RANGE key]",
	_pf_ddblsh_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some l in flatten_list(name, "Properties.LocalSecondaryIndexes")
	ks := object.get(l.value, "KeySchema", [])
	count(ks) > 0
	_pf_ddblsh_resolvable_all(ks)
	not "RANGE" in _pf_ddblsh_keytypes(ks)
	iname := object.get(l.value, "IndexName", "<unnamed>")
}

violation contains make_diag_full("pf-dynamodb-lsi-shape", "ERROR", name,
	sprintf("Properties.LocalSecondaryIndexes.%d.KeySchema", [l.index]),
	sprintf("Local secondary index '%s' uses hash key '%s' but the table's hash key is '%s'; CreateTable fails with \"Index KeySchema does not have the same leading hash key as table KeySchema\"", [iname, lsiHash, tableHash]),
	"An LSI must reuse the table's partition key; use a global secondary index for a different hash key",
	_pf_ddblsh_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some t in flatten_list(name, "Properties.KeySchema")
	t.index == 0
	tableHash := object.get(t.value, "AttributeName", null)
	is_string(tableHash)
	some l in flatten_list(name, "Properties.LocalSecondaryIndexes")
	ks := object.get(l.value, "KeySchema", [])
	some k in ks
	object.get(k, "KeyType", null) == "HASH"
	lsiHash := object.get(k, "AttributeName", null)
	is_string(lsiHash)
	lsiHash != tableHash
	iname := object.get(l.value, "IndexName", "<unnamed>")
}
