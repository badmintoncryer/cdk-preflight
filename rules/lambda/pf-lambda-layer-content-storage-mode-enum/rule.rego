package cdk_preflight

import rego.v1

_pf_llsm_fix := "Set S3ObjectStorageMode to COPY or REFERENCE"

_pf_llsm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-layerversion-content.html"

violation contains make_diag_full("pf-lambda-layer-content-storage-mode-enum", "ERROR", name,
	"Properties.Content.S3ObjectStorageMode",
	sprintf("S3ObjectStorageMode '%v'; Lambda either copies the archive (COPY) or reads it in place (REFERENCE)", [v]),
	_pf_llsm_fix, _pf_llsm_url) if {
	some name in _pf_lam_layer
	c := _pf_lam_obj(_pf_lam_props(name), "Content")
	v := object.get(c, "S3ObjectStorageMode", "COPY")
	is_string(v)
	not v in {"COPY", "REFERENCE"}
}
