package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-duplicate-attribute-definitions", "ERROR", name,
	sprintf("Properties.AttributeDefinitions.%d", [b.index]),
	sprintf("Attribute '%s' appears more than once in AttributeDefinitions; CreateTable fails with \"An attribute appears more than once in AttributeDefinitions\"", [an]),
	"Keep a single definition per attribute name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some a in flatten_list(name, "Properties.AttributeDefinitions")
	some b in flatten_list(name, "Properties.AttributeDefinitions")
	a.index < b.index
	an := object.get(a.value, "AttributeName", null)
	is_string(an)
	object.get(b.value, "AttributeName", null) == an
}
