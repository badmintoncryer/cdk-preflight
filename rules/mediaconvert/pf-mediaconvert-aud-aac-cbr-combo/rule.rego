package cdk_preflight

import rego.v1

_pf_mc_aud_aac_cbr_combo_url := "https://docs.aws.amazon.com/mediaconvert/latest/ug/aac-support.html"

_pf_mcac_cbr contains {"rn": a.rn, "i": a.i, "key": key, "aac": a.aac} if {
	some a in _pf_mclib_aac
	object.get(a.aac, "RateControlMode", "CBR") == "CBR"
	profile := object.get(a.aac, "CodecProfile", "LC")
	profile in {"LC", "HEV1", "HEV2"}
	mode := _pf_mclib_aac_mode[a.aac.CodingMode]
	sr := a.aac.SampleRate
	is_number(sr)
	key := sprintf("%s|%s|%d", [profile, mode, sr])
}

violation contains make_diag_full("pf-mediaconvert-aud-aac-cbr-combo", "ERROR", c.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.AacSettings.SampleRate", [c.i]),
	sprintf("AAC CBR has no supported combination for %s (CodecProfile|CodingMode|SampleRate)", [c.key]),
	"Use a CodecProfile, CodingMode and SampleRate combination from the AAC support table", _pf_mc_aud_aac_cbr_combo_url) if {
	some c in _pf_mcac_cbr
	not _pf_mclib_aac_cbr[c.key]
}

violation contains make_diag_full("pf-mediaconvert-aud-aac-cbr-combo", "ERROR", c.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.CodecSettings.AacSettings.Bitrate", [c.i]),
	sprintf("AAC CBR Bitrate %v is outside %d-%d for %s (CodecProfile|CodingMode|SampleRate)", [br, r[0], r[1], c.key]),
	sprintf("Set Bitrate between %d and %d", [r[0], r[1]]), _pf_mc_aud_aac_cbr_combo_url) if {
	some c in _pf_mcac_cbr
	r := _pf_mclib_aac_cbr[c.key]
	br := c.aac.Bitrate
	is_number(br)
	_pf_mcac_out(br, r)
}

_pf_mcac_out(br, r) if br < r[0]

_pf_mcac_out(br, r) if br > r[1]
