package cdk_preflight

import rego.v1

# W3030/WARN in the bundled engine (1.7.0-beta) — does not block the deploy.
violation contains make_diag_full("pf-dynamodb-table-class", "ERROR", name,
	"Properties.TableClass",
	sprintf("TableClass '%s' does not exist; CreateTable fails with \"Invalid table-class parameter provided\"", [tc]),
	"Use STANDARD or STANDARD_INFREQUENT_ACCESS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	tc := resolve(name, "Properties.TableClass")
	is_string(tc)
	not tc in {"STANDARD", "STANDARD_INFREQUENT_ACCESS"}
}
