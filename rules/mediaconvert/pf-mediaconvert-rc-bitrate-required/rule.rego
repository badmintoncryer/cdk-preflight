package cdk_preflight

import rego.v1

_pf_mc_rc_bitrate_required_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcrb_blocks := {
	"H_264": "H264Settings",
	"H_265": "H265Settings",
	"MPEG2": "Mpeg2Settings",
}

violation contains make_diag_full("pf-mediaconvert-rc-bitrate-required", "ERROR", rn, sprintf("Properties.SettingsJson.VideoDescription.CodecSettings.%s.RateControlMode", [blk]),
	sprintf("%s.RateControlMode is %s but Bitrate is not set; Bitrate is required for CBR and VBR", [blk, mode]),
	sprintf("Set %s.Bitrate (or use another RateControlMode)", [blk]), _pf_mc_rc_bitrate_required_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cs := _pf_mclib_vcs(rn)
	codec := cs.Codec
	is_string(codec)
	blk := _pf_mcrb_blocks[codec]
	st := cs[blk]
	_pf_mclib_lit(st)
	mode := st.RateControlMode
	mode in {"CBR", "VBR"}
	object.get(st, "Bitrate", "__pf_absent") == "__pf_absent"
}
