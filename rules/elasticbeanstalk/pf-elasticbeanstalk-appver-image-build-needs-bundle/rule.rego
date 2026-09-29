package cdk_preflight

import rego.v1

_pf_eb_appver_image_build_needs_bundle_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ImageBuildConfiguration.html"

violation contains make_diag_full("pf-elasticbeanstalk-appver-image-build-needs-bundle", "ERROR", name, "Properties.ImageConfiguration.Build",
	"ImageConfiguration.Build builds the image from a source bundle but SourceBundle is not set; CreateApplicationVersion rejects the version",
	"Add SourceBundle (S3Bucket / S3Key) next to ImageConfiguration.Build", _pf_eb_appver_image_build_needs_bundle_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ApplicationVersion")
	p := _pf_eblib_props(name)
	_pf_eblib_lit_obj(object.get(p, "ImageConfiguration", null))
	_pf_eblib_lit_obj(p.ImageConfiguration.Build)
	object.get(p, "SourceBundle", "__pf_absent") == "__pf_absent"
}
