package cdk_preflight

import rego.v1

_pf_mc_job_dynamic_audio_selector_language_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

violation contains make_diag_full("pf-mediaconvert-job-dynamic-audio-selector-language", "ERROR", i.rn, sprintf("Properties.SettingsJson.Inputs.%d.DynamicAudioSelectors.%s", [i.i, name]),
	sprintf("Dynamic audio selector '%s' has SelectorType LANGUAGE_CODE but no LanguageCode", [name]),
	"Set LanguageCode on the selector, or use SelectorType ALL_TRACKS", _pf_mc_job_dynamic_audio_selector_language_url) if {
	some i in _pf_mclib_inputs
	das := i["in"].DynamicAudioSelectors
	_pf_mclib_lit(das)
	some name, sel in das
	_pf_mclib_lit(sel)
	sel.SelectorType == "LANGUAGE_CODE"
	object.get(sel, "LanguageCode", "__pf_absent") == "__pf_absent"
}
