package cdk_preflight

import rego.v1

_pf_eb_appver_image_buildpack_required_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ImageBuildConfiguration.html"

violation contains make_diag_full("pf-elasticbeanstalk-appver-image-buildpack-required", "ERROR", name, "Properties.ImageConfiguration.Build",
	"ImageConfiguration.Build.Type is buildpack but Buildpack is not set; the builder image is required for buildpack builds and CreateApplicationVersion rejects the version",
	"Set Build.Buildpack, for example paketobuildpacks/builder-jammy-base", _pf_eb_appver_image_buildpack_required_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ApplicationVersion")
	p := _pf_eblib_props(name)
	_pf_eblib_lit_obj(object.get(p, "ImageConfiguration", null))
	b := p.ImageConfiguration.Build
	_pf_eblib_lit_obj(b)
	b.Type == "buildpack"
	object.get(b, "Buildpack", "__pf_absent") == "__pf_absent"
}
