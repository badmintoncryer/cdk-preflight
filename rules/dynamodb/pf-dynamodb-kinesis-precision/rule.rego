package cdk_preflight

import rego.v1

# W3030/WARN in the bundled engine (1.7.0-beta) — does not block the deploy.
violation contains make_diag_full("pf-dynamodb-kinesis-precision", "ERROR", name,
	"Properties.KinesisStreamSpecification.ApproximateCreationDateTimePrecision",
	sprintf("ApproximateCreationDateTimePrecision '%s' does not exist; EnableKinesisStreamingDestination rejects the value", [p]),
	"Use MICROSECOND or MILLISECOND",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-kinesisstreamspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	p := resolve(name, "Properties.KinesisStreamSpecification.ApproximateCreationDateTimePrecision")
	is_string(p)
	not p in {"MICROSECOND", "MILLISECOND"}
}
