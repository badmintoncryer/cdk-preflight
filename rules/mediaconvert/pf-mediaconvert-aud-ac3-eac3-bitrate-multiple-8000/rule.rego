package cdk_preflight

import rego.v1

_pf_mc_aud_ac3_eac3_bitrate_multiple_8000_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcac3b_block := {
	"AC3": "Ac3Settings",
	"EAC3": "Eac3Settings",
}

violation contains make_diag_full("pf-mediaconvert-aud-ac3-eac3-bitrate-multiple-8000", "ERROR", a.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.%s.Bitrate", [a.i, blk]),
	sprintf("%s.Bitrate is %v; it must be a multiple of 8000", [blk, br]),
	"Round Bitrate to a multiple of 8000", _pf_mc_aud_ac3_eac3_bitrate_multiple_8000_url) if {
	some a in _pf_mclib_ads
	cs := a.ad.CodecSettings
	_pf_mclib_lit(cs)
	blk := _pf_mcac3b_block[cs.Codec]
	st := cs[blk]
	_pf_mclib_lit(st)
	br := st.Bitrate
	is_number(br)
	br % 8000 != 0
}
