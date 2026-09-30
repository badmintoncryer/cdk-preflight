package cdk_preflight

import rego.v1

_pf_mc_cap_dvbsub_dds_coordinates_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

_pf_mcdd_keys := ["DdsXCoordinate", "DdsYCoordinate", "Width", "Height"]

violation contains make_diag_full("pf-mediaconvert-cap-dvbsub-dds-coordinates", "ERROR", rn, sprintf("Properties.SettingsJson.CaptionDescriptions.%d.DestinationSettings.DvbSubDestinationSettings.%s", [i, k]),
	sprintf("DvbSubDestinationSettings.%s is set but DdsHandling is NONE (the default); the service rejects DDS coordinates and size when DdsHandling is NONE", [k]),
	"Set DdsHandling to SPECIFIED (or another value other than NONE), or remove DdsXCoordinate, DdsYCoordinate, Width and Height", _pf_mc_cap_dvbsub_dds_coordinates_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	s := _pf_mclib_settings(rn, "AWS::MediaConvert::Preset")
	cds := s.CaptionDescriptions
	is_array(cds)
	some i, cd in cds
	_pf_mclib_lit(cd)
	ds := cd.DestinationSettings
	_pf_mclib_lit(ds)
	dv := ds.DvbSubDestinationSettings
	_pf_mclib_lit(dv)
	object.get(dv, "DdsHandling", "NONE") == "NONE"
	some k in _pf_mcdd_keys
	is_number(dv[k])
	dv[k] != 0
}
