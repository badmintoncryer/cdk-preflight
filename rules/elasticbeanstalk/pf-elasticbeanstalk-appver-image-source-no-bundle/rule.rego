package cdk_preflight

import rego.v1

_pf_eb_appver_image_source_no_bundle_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ImageConfiguration.html"

violation contains make_diag_full("pf-elasticbeanstalk-appver-image-source-no-bundle", "ERROR", name, "Properties.SourceBundle",
	"ImageConfiguration.Source takes a prebuilt container image, so SourceBundle cannot be set as well; CreateApplicationVersion rejects the combination",
	"Drop SourceBundle, or use ImageConfiguration.Build to build from it", _pf_eb_appver_image_source_no_bundle_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ApplicationVersion")
	p := _pf_eblib_props(name)
	_pf_eblib_lit_obj(object.get(p, "ImageConfiguration", null))
	_pf_eblib_lit_obj(p.ImageConfiguration.Source)
	object.get(p, "SourceBundle", "__pf_absent") != "__pf_absent"
}
