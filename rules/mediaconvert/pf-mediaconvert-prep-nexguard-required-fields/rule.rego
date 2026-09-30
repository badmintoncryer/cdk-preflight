package cdk_preflight

import rego.v1

_pf_mc_prep_nexguard_required_fields_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-prep-nexguard-required-fields", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.PartnerWatermarking.NexguardFileMarkerSettings.License",
	"NexguardFileMarkerSettings is set but License is missing; License is required",
	"Set NexguardFileMarkerSettings.License", _pf_mc_prep_nexguard_required_fields_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	pw := _pf_mclib_vp(rn).PartnerWatermarking
	_pf_mclib_lit(pw)
	nx := pw.NexguardFileMarkerSettings
	_pf_mclib_lit(nx)
	object.get(nx, "License", "__pf_absent") == "__pf_absent"
}
