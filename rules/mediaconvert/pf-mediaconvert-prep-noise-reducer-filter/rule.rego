package cdk_preflight

import rego.v1

_pf_mc_prep_noise_reducer_filter_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-prep-noise-reducer-filter", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.NoiseReducer.SpatialFilterSettings",
	sprintf("NoiseReducer.Filter is %s but SpatialFilterSettings is set; SpatialFilterSettings needs Filter SPATIAL", [f]),
	"Set NoiseReducer.Filter to SPATIAL, or remove SpatialFilterSettings", _pf_mc_prep_noise_reducer_filter_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	nr := _pf_mclib_vp(rn).NoiseReducer
	_pf_mclib_lit(nr)
	f := nr.Filter
	is_string(f)
	f != "SPATIAL"
	_pf_mclib_lit(nr.SpatialFilterSettings)
}
