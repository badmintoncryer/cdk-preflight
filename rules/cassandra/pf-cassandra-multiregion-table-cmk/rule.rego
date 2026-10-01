package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-multiregion-table-cmk", "ERROR", name, "Properties.EncryptionSpecification.EncryptionType",
	"the table is in a MULTI_REGION keyspace but uses CUSTOMER_MANAGED_KMS_KEY; Keyspaces answers \"Customer managed KMS key encryption type is not supported on multi region table\"",
	"Use AWS_OWNED_KMS_KEY for multi-Region tables",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/multiRegion-replication_usage-notes.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	enc := object.get(input.resources[name].properties, "EncryptionSpecification", null)
	is_object(enc)
	object.get(enc, "EncryptionType", null) == "CUSTOMER_MANAGED_KMS_KEY"
	_pf_cass_mr(_pf_cass_ks(name))
}
