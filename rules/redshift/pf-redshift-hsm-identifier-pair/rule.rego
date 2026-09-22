package cdk_preflight

import rego.v1

_pf_rshsm_msg := "only one of HsmClientCertificateIdentifier / HsmConfigurationIdentifier is set; CreateCluster rejects it (\"Either both HsmClientCertificateIdentifier and HsmConfigurationIdentifier should be provided for a cluster using an HSM, or neither should be provided for a cluster not using an HSM.\")"

_pf_rshsm_fix := "Set both HSM identifiers, or neither"

violation contains make_diag_full("pf-redshift-hsm-identifier-pair", "ERROR", name,
	"Properties.HsmClientCertificateIdentifier", _pf_rshsm_msg, _pf_rshsm_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-cluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_has(name, "HsmClientCertificateIdentifier")
	not _pf_redshiftlib_has(name, "HsmConfigurationIdentifier")
}

violation contains make_diag_full("pf-redshift-hsm-identifier-pair", "ERROR", name,
	"Properties.HsmConfigurationIdentifier", _pf_rshsm_msg, _pf_rshsm_fix, "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-redshift-cluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_has(name, "HsmConfigurationIdentifier")
	not _pf_redshiftlib_has(name, "HsmClientCertificateIdentifier")
}
