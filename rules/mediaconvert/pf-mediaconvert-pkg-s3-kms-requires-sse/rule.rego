package cdk_preflight

import rego.v1

_pf_mc_pkg_s3_kms_requires_sse_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/outputs-file-group.html"

_pf_mcs3k_keys := ["KmsKeyArn", "KmsEncryptionContext"]

violation contains make_diag_full("pf-mediaconvert-pkg-s3-kms-requires-sse", "ERROR", grp.rn, sprintf("Properties.SettingsJson.OutputGroups.%d.OutputGroupSettings.FileGroupSettings.DestinationSettings.S3Settings.Encryption.%s", [grp.i, k]),
	sprintf("S3Settings.Encryption sets %s but EncryptionType is %s; a KMS key or encryption context is only accepted with SERVER_SIDE_ENCRYPTION_KMS", [k, t]),
	"Set EncryptionType to SERVER_SIDE_ENCRYPTION_KMS, or remove the KMS settings", _pf_mc_pkg_s3_kms_requires_sse_url) if {
	some grp in _pf_mclib_groups
	fg := grp.gs.FileGroupSettings
	_pf_mclib_lit(fg)
	ds := fg.DestinationSettings
	_pf_mclib_lit(ds)
	s3 := ds.S3Settings
	_pf_mclib_lit(s3)
	enc := s3.Encryption
	_pf_mclib_lit(enc)
	t := enc.EncryptionType
	is_string(t)
	t != "SERVER_SIDE_ENCRYPTION_KMS"
	some k in _pf_mcs3k_keys
	_pf_mclib_present(enc[k])
}
