package cdk_preflight

import rego.v1

# A witness is part of the MRSC quorum; an eventually consistent global table
# has nothing to do with one.
violation contains make_diag_full("pf-dynamodb-global-table-witness-requires-mrsc", "ERROR", name,
	"Properties.GlobalTableWitnesses",
	"GlobalTableWitnesses is set but MultiRegionConsistency is not STRONG; witnesses only exist in multi-Region strong consistency global tables",
	"Set MultiRegionConsistency to STRONG (with exactly three Regions), or drop GlobalTableWitnesses",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-globaltablewitness.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	count(flatten_list(name, "Properties.GlobalTableWitnesses")) > 0
	not _pf_ddb_mrsc(name)
}
