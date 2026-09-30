package cdk_preflight

import rego.v1

_pf_mc_job_nielsen_required_fields_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/jobtemplates.html"

_pf_mcnl_nl(rn) := nl if {
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::JobTemplate")
	nl := s.NielsenNonLinearWatermark
	_pf_mclib_lit(nl)
}

violation contains make_diag_full("pf-mediaconvert-job-nielsen-required-fields", "ERROR", rn, "Properties.SettingsJson.NielsenNonLinearWatermark.SourceId",
	"NielsenNonLinearWatermark.ActiveWatermarkProcess is NAES2_AND_NW but SourceId is missing; SourceId is required",
	"Set NielsenNonLinearWatermark.SourceId", _pf_mc_job_nielsen_required_fields_url) if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	nl := _pf_mcnl_nl(rn)
	nl.ActiveWatermarkProcess == "NAES2_AND_NW"
	object.get(nl, "SourceId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-mediaconvert-job-nielsen-required-fields", "ERROR", rn, "Properties.SettingsJson.NielsenNonLinearWatermark.CbetSourceId",
	"NielsenNonLinearWatermark.ActiveWatermarkProcess is CBET but CbetSourceId is missing; CbetSourceId is required",
	"Set NielsenNonLinearWatermark.CbetSourceId", _pf_mc_job_nielsen_required_fields_url) if {
	some rn in resources_of_type("AWS::MediaConvert::JobTemplate")
	nl := _pf_mcnl_nl(rn)
	nl.ActiveWatermarkProcess == "CBET"
	object.get(nl, "CbetSourceId", "__pf_absent") == "__pf_absent"
}
