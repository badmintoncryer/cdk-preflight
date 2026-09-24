package cdk_preflight

import rego.v1

_pf_cfgstv_err := "the rule create fails: a tag value on its own does not name a tag"

violation contains make_diag_full("pf-config-rule-scope-tag-value-requires-tag-key", "ERROR", name,
	"Properties.Scope.TagValue",
	sprintf("Scope sets TagValue without TagKey; %s", [_pf_cfgstv_err]),
	"Set Scope.TagKey as well, or drop TagValue",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configrule-scope.html") if {
	some name in resources_of_type("AWS::Config::ConfigRule")
	sc := _pf_cfglib_scope(name)
	_pf_cfglib_present(sc, "TagValue")
	not _pf_cfglib_present(sc, "TagKey")
}
