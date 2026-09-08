package cdk_preflight

import rego.v1

# The CFN schema carries Maximum 20 for NonKeyAttributes but the bundled
# engine does not evaluate it (measured 2026-09-08, 1.7.0-beta).
violation contains make_diag_full("pf-dynamodb-projection-nonkey-limit", "ERROR", name,
	sprintf("Properties.%s.%d.Projection.NonKeyAttributes", [prop, ix.index]),
	sprintf("Index '%s' projects %d non-key attributes; CreateTable fails with \"Member must have length less than or equal to 20\"", [iname, n]),
	"Project at most 20 non-key attributes per index, or switch the index to ProjectionType ALL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-projection.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	proj := object.get(ix.value, "Projection", null)
	is_object(proj)
	n := count(object.get(proj, "NonKeyAttributes", []))
	n > 20
	iname := object.get(ix.value, "IndexName", "<unnamed>")
}
