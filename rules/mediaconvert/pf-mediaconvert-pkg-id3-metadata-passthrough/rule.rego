package cdk_preflight

import rego.v1

_pf_mc_pkg_id3_metadata_passthrough_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

# TimedMetadata が未指定か NONE（既定は NONE）の CMFC / MPD だけを見る
_pf_mcid3_cm(rn) := cm if {
	_pf_mclib_container(rn) == "CMFC"
	cm := _pf_mclib_cont(rn).CmfcSettings
	_pf_mclib_lit(cm)
	object.get(cm, "TimedMetadata", "NONE") == "NONE"
}

_pf_mcid3_mp(rn) := mp if {
	_pf_mclib_container(rn) == "MPD"
	mp := _pf_mclib_cont(rn).MpdSettings
	_pf_mclib_lit(mp)
	object.get(mp, "TimedMetadata", "NONE") == "NONE"
}

violation contains make_diag_full("pf-mediaconvert-pkg-id3-metadata-passthrough", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.CmfcSettings.TimedMetadataValue",
	"CmfcSettings.TimedMetadataValue is set but TimedMetadata is not PASSTHROUGH; an ID3 metadata value needs ID3 metadata set to Passthrough",
	"Set CmfcSettings.TimedMetadata to PASSTHROUGH, or remove TimedMetadataValue", _pf_mc_pkg_id3_metadata_passthrough_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cm := _pf_mcid3_cm(rn)
	is_string(cm.TimedMetadataValue)
}

violation contains make_diag_full("pf-mediaconvert-pkg-id3-metadata-passthrough", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.CmfcSettings.TimedMetadataBoxVersion",
	"CmfcSettings.TimedMetadataBoxVersion is VERSION_1 but TimedMetadata is not PASSTHROUGH; box version 1 needs ID3 metadata set to Passthrough",
	"Set CmfcSettings.TimedMetadata to PASSTHROUGH, or set TimedMetadataBoxVersion to VERSION_0", _pf_mc_pkg_id3_metadata_passthrough_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cm := _pf_mcid3_cm(rn)
	cm.TimedMetadataBoxVersion == "VERSION_1"
}

violation contains make_diag_full("pf-mediaconvert-pkg-id3-metadata-passthrough", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.CmfcSettings.ManifestMetadataSignaling",
	"CmfcSettings.ManifestMetadataSignaling is ENABLED but no timed metadata source is set; it needs Scte35Source PASSTHROUGH, Scte35Esam INSERT or TimedMetadata PASSTHROUGH",
	"Set one of Scte35Source PASSTHROUGH, Scte35Esam INSERT or TimedMetadata PASSTHROUGH, or set ManifestMetadataSignaling to DISABLED", _pf_mc_pkg_id3_metadata_passthrough_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	cm := _pf_mcid3_cm(rn)
	cm.ManifestMetadataSignaling == "ENABLED"
	object.get(cm, "Scte35Source", "NONE") == "NONE"
	object.get(cm, "Scte35Esam", "NONE") == "NONE"
}

violation contains make_diag_full("pf-mediaconvert-pkg-id3-metadata-passthrough", "ERROR", rn, "Properties.SettingsJson.ContainerSettings.MpdSettings.TimedMetadataSchemeIdUri",
	"MpdSettings.TimedMetadataSchemeIdUri is set but TimedMetadata is not PASSTHROUGH; the ID3 scheme ID URI needs ID3 metadata set to Passthrough",
	"Set MpdSettings.TimedMetadata to PASSTHROUGH, or remove TimedMetadataSchemeIdUri", _pf_mc_pkg_id3_metadata_passthrough_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	mp := _pf_mcid3_mp(rn)
	is_string(mp.TimedMetadataSchemeIdUri)
}
