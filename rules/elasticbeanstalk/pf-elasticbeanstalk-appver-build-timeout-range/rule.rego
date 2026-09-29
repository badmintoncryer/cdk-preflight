package cdk_preflight

import rego.v1

_pf_eb_appver_build_timeout_range_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ImageBuildConfiguration.html"

violation contains make_diag_full("pf-elasticbeanstalk-appver-build-timeout-range", "ERROR", name, "Properties.ImageConfiguration.Build.TimeoutInMinutes",
	sprintf("ImageConfiguration.Build.TimeoutInMinutes is %v; the image build timeout must be between 5 and 480 minutes", [n]),
	"Use a timeout of 5 to 480 minutes", _pf_eb_appver_build_timeout_range_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ApplicationVersion")
	p := _pf_eblib_props(name)
	_pf_eblib_lit_obj(object.get(p, "ImageConfiguration", null))
	b := p.ImageConfiguration.Build
	_pf_eblib_lit_obj(b)
	n := _pf_eblib_numv(object.get(b, "TimeoutInMinutes", null))
	n < 5
}

violation contains make_diag_full("pf-elasticbeanstalk-appver-build-timeout-range", "ERROR", name, "Properties.ImageConfiguration.Build.TimeoutInMinutes",
	sprintf("ImageConfiguration.Build.TimeoutInMinutes is %v; the image build timeout must be between 5 and 480 minutes", [n]),
	"Use a timeout of 5 to 480 minutes", _pf_eb_appver_build_timeout_range_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ApplicationVersion")
	p := _pf_eblib_props(name)
	_pf_eblib_lit_obj(object.get(p, "ImageConfiguration", null))
	b := p.ImageConfiguration.Build
	_pf_eblib_lit_obj(b)
	n := _pf_eblib_numv(object.get(b, "TimeoutInMinutes", null))
	n > 480
}
