package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-encryption-kms-key-symmetric", "ERROR", name, "Properties.EncryptionSpecification.KmsKeyIdentifier",
	sprintf("KmsKeyIdentifier points at the KMS key %v with KeySpec %v / KeyUsage %v; Keyspaces answers \"Specified encryption key is not symmetric\"", [k, ks, ku]),
	"Point KmsKeyIdentifier at a SYMMETRIC_DEFAULT key",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/encryption.customermanaged.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	k := resolve(name, "Properties.EncryptionSpecification.KmsKeyIdentifier")
	k in resources_of_type("AWS::KMS::Key")
	p := input.resources[k].properties
	ks := object.get(p, "KeySpec", "SYMMETRIC_DEFAULT")
	ku := object.get(p, "KeyUsage", "ENCRYPT_DECRYPT")
	is_string(ks)
	is_string(ku)
	_pf_casskms_bad(ks, ku)
}

_pf_casskms_bad(ks, _) if ks != "SYMMETRIC_DEFAULT"

_pf_casskms_bad(_, ku) if ku != "ENCRYPT_DECRYPT"
