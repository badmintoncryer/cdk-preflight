package cdk_preflight

import rego.v1

_pf_mc_prep_clip_limits_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mccl_keys := ["MinimumYUV", "MaximumYUV", "MinimumRGBTolerance", "MaximumRGBTolerance"]

violation contains make_diag_full("pf-mediaconvert-prep-clip-limits", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.ColorCorrector.ClipLimits",
	sprintf("ColorCorrector.ClipLimits.%s is set but SampleRangeConversion is %s; clip limits only apply with LIMITED_RANGE_CLIP", [k, src]),
	"Set ColorCorrector.SampleRangeConversion to LIMITED_RANGE_CLIP, or remove ClipLimits", _pf_mc_prep_clip_limits_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cc := _pf_mclib_cc(rn)
	cl := cc.ClipLimits
	_pf_mclib_lit(cl)
	some k in _pf_mccl_keys
	is_number(cl[k])
	src := object.get(cc, "SampleRangeConversion", "NONE")
	is_string(src)
	src != "LIMITED_RANGE_CLIP"
}
