package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-volume-config-exclusive", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("volume %v carries %v configuration blocks (\"When the volume parameter is specified, only one volume configuration type should be used.\")", [object.get(v.value, "Name", v.index), n]),
	"Keep one of Host, EfsVolumeConfiguration or S3FilesVolumeConfiguration",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Volume.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	n := count([k | some k in ["Host", "EfsVolumeConfiguration", "S3FilesVolumeConfiguration"]; _pf_batch_ohas(v.value, k)])
	n > 1
}
