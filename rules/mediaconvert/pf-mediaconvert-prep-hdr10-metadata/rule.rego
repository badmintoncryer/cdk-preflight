package cdk_preflight

import rego.v1

_pf_mc_prep_hdr10_metadata_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mch1_cc(rn) := cc if {
	cc := _pf_mclib_cc(rn)
	cc.ColorSpaceConversion == "FORCE_HDR10"
}

violation contains make_diag_full("pf-mediaconvert-prep-hdr10-metadata", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.ColorCorrector.Hdr10Metadata",
	"ColorCorrector.ColorSpaceConversion is FORCE_HDR10 but Hdr10Metadata is not set; HDR10 needs MaxContentLightLevel and MaxFrameAverageLightLevel",
	"Add Hdr10Metadata with MaxContentLightLevel and MaxFrameAverageLightLevel", _pf_mc_prep_hdr10_metadata_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cc := _pf_mch1_cc(rn)
	object.get(cc, "Hdr10Metadata", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-mediaconvert-prep-hdr10-metadata", "ERROR", rn, "Properties.SettingsJson.VideoDescription.VideoPreprocessors.ColorCorrector.Hdr10Metadata.MaxFrameAverageLightLevel",
	"ColorCorrector.ColorSpaceConversion is FORCE_HDR10 but Hdr10Metadata.MaxFrameAverageLightLevel is not set; HDR10 needs both light levels",
	"Set Hdr10Metadata.MaxFrameAverageLightLevel", _pf_mc_prep_hdr10_metadata_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cc := _pf_mch1_cc(rn)
	hm := cc.Hdr10Metadata
	_pf_mclib_lit(hm)
	object.get(hm, "MaxFrameAverageLightLevel", "__pf_absent") == "__pf_absent"
}
