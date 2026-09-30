package cdk_preflight

import rego.v1

_pf_mc_prep_image_inserter_xy_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/presets.html"

violation contains make_diag_full("pf-mediaconvert-prep-image-inserter-xy", "ERROR", rn, sprintf("Properties.SettingsJson.VideoDescription.VideoPreprocessors.ImageInserter.InsertableImages.%d.%s", [j, k]),
	sprintf("InsertableImages[%d] has no %s; ImageX and ImageY are both required", [j, k]),
	sprintf("Set %s on the inserted image", [k]), _pf_mc_prep_image_inserter_xy_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Preset")
	ii := _pf_mclib_vp(rn).ImageInserter
	_pf_mclib_lit(ii)
	imgs := ii.InsertableImages
	is_array(imgs)
	some j, im in imgs
	_pf_mclib_lit(im)
	some k in ["ImageX", "ImageY"]
	object.get(im, k, "__pf_absent") == "__pf_absent"
}
