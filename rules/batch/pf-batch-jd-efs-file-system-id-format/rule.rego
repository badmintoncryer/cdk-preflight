package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-efs-file-system-id-format", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("FileSystemId %v is not an EFS file system id (\"EFS configuration fileSystemId is not valid: %v.\")", [fsid, fsid]),
	"Reference the file system id (fs-\u2026)",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EFSVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	fsid := _pf_batch_oget(_pf_batch_efs(v), "FileSystemId")
	_pf_batch_lit(fsid)
	not regex.match(`^fs-[0-9a-f]+$`, fsid)
}
