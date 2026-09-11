package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-efs-access-point-root-directory", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("volume %v sets RootDirectory %v together with an access point (\"When using an EFS access point, the root directory must either be set to \\\"/\\\" or omitted\")", [object.get(v.value, "Name", v.index), rd]),
	"Drop RootDirectory, or set it to /",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EFSVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	e := _pf_batch_efs(v)
	_pf_batch_ohas(_pf_batch_oget(e, "AuthorizationConfig"), "AccessPointId")
	rd := _pf_batch_oget(e, "RootDirectory")
	_pf_batch_lit(rd)
	not rd in {"/", ""}
}
