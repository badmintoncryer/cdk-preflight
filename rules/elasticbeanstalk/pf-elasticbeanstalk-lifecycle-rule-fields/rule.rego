package cdk_preflight

import rego.v1

_pf_eb_lifecycle_rule_fields_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ApplicationResourceLifecycleConfig.html"

violation contains make_diag_full("pf-elasticbeanstalk-lifecycle-rule-fields", "ERROR", name, sprintf("Properties.ResourceLifecycleConfig.VersionLifecycleConfig.%s", [rk]),
	sprintf("%s is enabled but %s is not set; an enabled lifecycle rule needs a value of at least 1", [rk, fld]),
	sprintf("Set %s to 1 or more, or disable the rule", [fld]), _pf_eb_lifecycle_rule_fields_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::Application")
	vc := object.get(object.get(_pf_eblib_props(name), "ResourceLifecycleConfig", {}), "VersionLifecycleConfig", null)
	_pf_eblib_lit_obj(vc)
	some rk, fld in _pf_eblib_lc_field
	r := object.get(vc, rk, null)
	_pf_eblib_lit_obj(r)
	_pf_eblib_lc_enabled(r)
	object.get(r, fld, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-elasticbeanstalk-lifecycle-rule-fields", "ERROR", name, sprintf("Properties.ResourceLifecycleConfig.VersionLifecycleConfig.%s.%s", [rk, fld]),
	sprintf("%s.%s is %v; an enabled lifecycle rule needs a value of at least 1", [rk, fld, n]),
	sprintf("Set %s to 1 or more, or disable the rule", [fld]), _pf_eb_lifecycle_rule_fields_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::Application")
	vc := object.get(object.get(_pf_eblib_props(name), "ResourceLifecycleConfig", {}), "VersionLifecycleConfig", null)
	_pf_eblib_lit_obj(vc)
	some rk, fld in _pf_eblib_lc_field
	r := object.get(vc, rk, null)
	_pf_eblib_lit_obj(r)
	_pf_eblib_lc_enabled(r)
	n := _pf_eblib_numv(object.get(r, fld, null))
	n < 1
}

violation contains make_diag_full("pf-elasticbeanstalk-lifecycle-rule-fields", "ERROR", name, "Properties.ResourceLifecycleConfig.VersionLifecycleConfig",
	"MaxAgeRule and MaxCountRule are both enabled; Elastic Beanstalk allows only one enabled version lifecycle rule and rejects the pair",
	"Enable one of MaxAgeRule and MaxCountRule", _pf_eb_lifecycle_rule_fields_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::Application")
	vc := object.get(object.get(_pf_eblib_props(name), "ResourceLifecycleConfig", {}), "VersionLifecycleConfig", null)
	_pf_eblib_lit_obj(vc)
	a := object.get(vc, "MaxAgeRule", null)
	c := object.get(vc, "MaxCountRule", null)
	_pf_eblib_lit_obj(a)
	_pf_eblib_lit_obj(c)
	_pf_eblib_lc_enabled(a)
	_pf_eblib_lc_enabled(c)
}
