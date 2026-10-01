package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-encryption-type-key-consistency", "ERROR", name, "Properties.EncryptionSpecification",
	"EncryptionType is CUSTOMER_MANAGED_KMS_KEY but KmsKeyIdentifier is missing; the table create fails with \"EncryptionSpecification is invalid\"",
	"Set KmsKeyIdentifier to the key ARN, or use AWS_OWNED_KMS_KEY",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.ddl.table.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	enc := object.get(input.resources[name].properties, "EncryptionSpecification", null)
	is_object(enc)
	object.get(enc, "EncryptionType", null) == "CUSTOMER_MANAGED_KMS_KEY"
	object.get(enc, "KmsKeyIdentifier", null) == null
}
