package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-linked-resource-required", "ERROR", name, "Properties.Definition.TemplateLinked.Resource",
	sprintf("policy template %v declares ?resource, so this template-linked policy has to supply Resource; CreatePolicy answers \"Invalid Parameter: resource\"", [tname]),
	"Add Definition.TemplateLinked.Resource with the EntityType and EntityId that ?resource stands for",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, tname, slots] in _pf_cedarlib_links
	"?resource" in slots
	tl := _pf_cedarlib_tl(name)
	object.get(tl, "Resource", "__pf_absent") == "__pf_absent"
}
