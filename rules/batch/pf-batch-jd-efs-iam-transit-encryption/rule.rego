package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-efs-iam-transit-encryption", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("volume %v enables EFS IAM authorization without TransitEncryption ENABLED (\"EFS IAM authorization requires TransitEncryption to be enabled.\")", [object.get(v.value, "Name", v.index)]),
	"Set EfsVolumeConfiguration.TransitEncryption to ENABLED",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EFSAuthorizationConfig.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	e := _pf_batch_efs(v)
	_pf_batch_oget(_pf_batch_oget(e, "AuthorizationConfig"), "Iam") == "ENABLED"
	object.get(e, "TransitEncryption", "DISABLED") != "ENABLED"
}
