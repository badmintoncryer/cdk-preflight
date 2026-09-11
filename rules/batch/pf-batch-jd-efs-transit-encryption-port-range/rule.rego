package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-efs-transit-encryption-port-range", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("TransitEncryptionPort is %v (\"TransitEncryptionPort must be a valid port number.\")", [p]),
	"Use a port between 0 and 65535",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EFSVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	p := to_number(_pf_batch_oget(_pf_batch_efs(v), "TransitEncryptionPort"))
	_pf_batch_outside(p, 0, 65535)
}
