package cdk_preflight

import rego.v1

# MREC replicates by reading each replica's stream, so the stream is not
# optional once a second replica exists. MRSC does not replicate through
# streams and is excluded.
_pf_ddbgst_has(name) if is_object(resolve(name, "Properties.StreamSpecification"))

violation contains make_diag_full("pf-dynamodb-global-table-stream-required", "ERROR", name,
	"Properties.StreamSpecification",
	sprintf("The global table has %d replicas but no StreamSpecification; multi-Region eventual consistency replicates through DynamoDB Streams", [n]),
	"Add StreamSpecification with StreamViewType NEW_AND_OLD_IMAGES",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	not _pf_ddb_mrsc(name)
	n := count(flatten_list(name, "Properties.Replicas"))
	n > 1
	not _pf_ddbgst_has(name)
}
