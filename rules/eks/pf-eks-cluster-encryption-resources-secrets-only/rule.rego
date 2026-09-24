package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-cluster-encryption-resources-secrets-only", "ERROR", name,
	"Properties.EncryptionConfig",
	sprintf("EncryptionConfig asks to encrypt %v; EKS only encrypts secrets (\"Invalid k8s resource for encryption\")", [r]),
	"List only secrets in EncryptionConfig.Resources",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-encryptionconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	some ec in flatten_list(name, "Properties.EncryptionConfig")
	rs := object.get(ec.value, "Resources", [])
	is_array(rs)
	some r in rs
	_pf_ekslib_lit(r)
	r != "secrets"
}
