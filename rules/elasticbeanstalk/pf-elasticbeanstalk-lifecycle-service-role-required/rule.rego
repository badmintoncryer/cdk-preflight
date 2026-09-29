package cdk_preflight

import rego.v1

_pf_eb_lifecycle_service_role_required_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ApplicationResourceLifecycleConfig.html"

violation contains make_diag_full("pf-elasticbeanstalk-lifecycle-service-role-required", "ERROR", name, "Properties.ResourceLifecycleConfig",
	"ResourceLifecycleConfig sets a version lifecycle rule but no ServiceRole; the role is required the first time a lifecycle configuration is given and CreateApplication rejects it",
	"Set ResourceLifecycleConfig.ServiceRole to a role Elastic Beanstalk can assume", _pf_eb_lifecycle_service_role_required_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::Application")
	rc := object.get(_pf_eblib_props(name), "ResourceLifecycleConfig", null)
	_pf_eblib_lit_obj(rc)
	object.get(rc, "ServiceRole", "__pf_absent") == "__pf_absent"
	vc := object.get(rc, "VersionLifecycleConfig", null)
	_pf_eblib_lit_obj(vc)
	_pf_eblib_lc_has_rule(vc)
}
