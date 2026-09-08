package cdk_preflight

import rego.v1

_pf_ddbskc_keyed(name) := {r.index |
	some r in flatten_list(name, "Properties.Replicas")
	sse := object.get(r.value, "SSESpecification", null)
	is_object(sse)
	object.get(sse, "KMSMasterKeyId", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-dynamodb-global-table-replica-sse-key-coverage", "ERROR", name,
	sprintf("Properties.Replicas.%d.SSESpecification", [r.index]),
	sprintf("Replica '%s' has no KMSMasterKeyId while other replicas do; a customer managed key must be given for every replica (keys are regional and cannot be shared)", [region]),
	"Add a KMS key from that replica's own Region, or drop the per-replica keys entirely",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-replicaspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	count(_pf_ddbskc_keyed(name)) > 0
	some r in flatten_list(name, "Properties.Replicas")
	not r.index in _pf_ddbskc_keyed(name)
	region := object.get(r.value, "Region", "<unknown>")
}
