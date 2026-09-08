package cdk_preflight

import rego.v1

# The cap is on the sum over every INCLUDE projection in the table: the same
# attribute projected into two indexes counts twice. ALL projections are
# exempt, so only INCLUDE entries are summed.
_pf_ddbpnt_counts(name, prop) := [c |
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	proj := object.get(ix.value, "Projection", null)
	is_object(proj)
	object.get(proj, "ProjectionType", null) == "INCLUDE"
	c := count(object.get(proj, "NonKeyAttributes", []))
]

_pf_ddbpnt_total(name) := sum(array.concat(
	_pf_ddbpnt_counts(name, "GlobalSecondaryIndexes"),
	_pf_ddbpnt_counts(name, "LocalSecondaryIndexes"),
))

violation contains make_diag_full("pf-dynamodb-projection-nonkey-total", "ERROR", name,
	"Properties.GlobalSecondaryIndexes",
	sprintf("The table's indexes project %d non-key attributes in total; CreateTable fails with \"Number of projected attributes in all indexes exceeds limit of 100\"", [n]),
	"Project fewer attributes, share indexes, or switch an index to ProjectionType ALL (ALL does not count towards the limit)",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	n := _pf_ddbpnt_total(name)
	n > 100
}
