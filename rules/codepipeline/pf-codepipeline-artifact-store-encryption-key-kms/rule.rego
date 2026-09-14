package cdk_preflight

import rego.v1

# KMS is the only encryption key type an artifact store accepts, and the enum is case-sensitive.
violation contains make_diag_full("pf-codepipeline-artifact-store-encryption-key-kms", "ERROR", name,
	"Properties.ArtifactStore.EncryptionKey.Type",
	sprintf("the artifact store EncryptionKey.Type is '%v'; CreatePipeline fails with \"Member must satisfy enum value set: [KMS]\"", [v]),
	"Set ArtifactStore.EncryptionKey.Type to KMS",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	v := _pf_cplib_storekeytype(_pf_cplib_props(name))
	v != "KMS"
}

# The cross-region form carries one store per region; the same enum applies.
violation contains make_diag_full("pf-codepipeline-artifact-store-encryption-key-kms", "ERROR", name,
	sprintf("Properties.ArtifactStores.%v.ArtifactStore.EncryptionKey.Type", [i]),
	sprintf("the artifact store for region '%v' has EncryptionKey.Type '%v'; CreatePipeline fails with \"Member must satisfy enum value set: [KMS]\"", [object.get(e, "Region", ""), v]),
	"Set ArtifactStore.EncryptionKey.Type to KMS",
	"https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-pipeline-structure.html") if {
	some name in resources_of_type("AWS::CodePipeline::Pipeline")
	some i, e in object.get(_pf_cplib_props(name), "ArtifactStores", [])
	v := _pf_cplib_storekeytype(e)
	v != "KMS"
}
