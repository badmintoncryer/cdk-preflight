package cdk_preflight

import rego.v1

_pf_mc_aud_remix_description_pair_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcrp_pairs := [
	["AudioDescriptionAudioChannel", "AudioDescriptionDataChannel"],
	["AudioDescriptionDataChannel", "AudioDescriptionAudioChannel"],
]

violation contains make_diag_full("pf-mediaconvert-aud-remix-description-pair", "ERROR", r.rn, sprintf("Properties.SettingsJson.AudioDescriptions.%d.RemixSettings.%s", [r.i, pair[0]]),
	sprintf("RemixSettings.%s is set without %s; the two audio description channels must be specified together", [pair[0], pair[1]]),
	sprintf("Also set RemixSettings.%s, or remove %s", [pair[1], pair[0]]), _pf_mc_aud_remix_description_pair_url) if {
	some r in _pf_mclib_remix
	some pair in _pf_mcrp_pairs
	is_number(r.rs[pair[0]])
	object.get(r.rs, pair[1], "__pf_absent") == "__pf_absent"
}
