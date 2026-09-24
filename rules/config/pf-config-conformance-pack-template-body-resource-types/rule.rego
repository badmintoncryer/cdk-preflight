package cdk_preflight

import rego.v1

_pf_cfgpk_allowed := {"AWS::Config::ConfigRule", "AWS::Config::RemediationConfiguration"}

# The pack body is a whole CloudFormation template (YAML or JSON) carried in a
# string, so no schema layer looks inside it.
# ponytail: a regex over "Type:" keys, not a parser - the engine has no
# yaml.unmarshal, and a Type key is the only place a template names a resource
# type. Upgrade path: parse the body if a YAML builtin ever lands.
_pf_cfgpk_types(body) := {t |
	some m in regex.find_all_string_submatch_n(`(?m)(^|[\s{,])"?Type"?\s*:\s*"?(AWS::[A-Za-z0-9:]+)`, body, -1)
	t := m[2]
}

_pf_cfgpk_err := "the conformance pack create fails: a pack deploys Config rules, not arbitrary resources"

violation contains make_diag_full("pf-config-conformance-pack-template-body-resource-types", "ERROR", name,
	"Properties.TemplateBody",
	sprintf("the conformance pack template declares %v; %s", [t, _pf_cfgpk_err]),
	"Keep only AWS::Config::ConfigRule and AWS::Config::RemediationConfiguration in the pack template",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-conformancepack.html") if {
	some name in resources_of_type("AWS::Config::ConformancePack")
	body := resolve(name, "Properties.TemplateBody")
	is_string(body)
	some t in _pf_cfgpk_types(body)
	not t in _pf_cfgpk_allowed
}
