package cdk_preflight

import rego.v1

# Each replica is encrypted with a key in its own Region: a KMS key ARN is
# regional and cannot be used from another Region. The replica's Region is in
# the template, so this needs no deploy-environment injection.
violation contains make_diag_full("pf-dynamodb-global-table-replica-sse-key-region", "ERROR", name,
	sprintf("Properties.Replicas.%d.SSESpecification.KMSMasterKeyId", [r.index]),
	sprintf("Replica '%s' points at a KMS key in '%s'; a replica can only be encrypted with a key from its own Region", [region, keyRegion]),
	"Give each replica a KMS key created in that replica's Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-replicassespecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some r in flatten_list(name, "Properties.Replicas")
	region := object.get(r.value, "Region", null)
	is_string(region)
	sse := object.get(r.value, "SSESpecification", null)
	is_object(sse)
	kid := object.get(sse, "KMSMasterKeyId", null)
	is_string(kid)
	parts := split(kid, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kms"
	keyRegion := parts[3]
	keyRegion != ""
	keyRegion != region
}
