package cdk_preflight

import rego.v1

# Only judged when TableName points at a table in the same template, which is
# the only place the two counts are visible together.
_pf_gluepvk_table(name) := t if {
	t := resolve(name, "Properties.TableName")
	t in resources_of_type("AWS::Glue::Table")
}

_pf_gluepvk_keys(t) := k if {
	ti := object.get(_pf_gluelib_props(t), "TableInput", {})
	k := object.get(ti, "PartitionKeys", [])
	is_array(k)
}

violation contains make_diag_full("pf-glue-partition-values-match-partition-keys", "ERROR", name,
	"Properties.PartitionInput.Values",
	sprintf("The partition has %d Values but table %v declares %d PartitionKeys; CreatePartition fails with \"The number of partition keys do not match the number of partition values\"", [count(vals), t, count(keys)]),
	"Give one value per partition key, in the order the keys are declared",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreatePartition.html") if {
	some name in resources_of_type("AWS::Glue::Partition")
	pi := _pf_gluelib_get(name, "PartitionInput")
	is_object(pi)
	vals := object.get(pi, "Values", [])
	is_array(vals)
	t := _pf_gluepvk_table(name)
	keys := _pf_gluepvk_keys(t)
	_pf_countable_items(vals)
	count(vals) != count(keys)
}
