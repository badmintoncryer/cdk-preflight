package cdk_preflight

import rego.v1

# The engine reports this enum as W3030/WARN only, which does not block the
# deploy — hence upstream: pending-engine. AWS::DynamoDB::Table only; the
# GlobalTable variant was not measured.
violation contains make_diag_full("pf-dynamodb-attribute-type", "ERROR", name,
	sprintf("Properties.AttributeDefinitions.%d.AttributeType", [d.index]),
	sprintf("AttributeType '%s' is not a key attribute type; CreateTable fails with \"Member must satisfy enum value set: [B, N, S]\"", [t]),
	"Use S (string), N (number) or B (binary) — key attributes cannot be lists, maps or booleans",
	"https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	t := object.get(d.value, "AttributeType", null)
	is_string(t)
	not t in {"S", "N", "B"}
}
