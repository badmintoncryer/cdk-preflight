package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-linked-principal-required", "ERROR", name, "Properties.Definition.TemplateLinked.Principal",
	sprintf("policy template %v declares ?principal, so this template-linked policy has to supply Principal; CreatePolicy answers \"Invalid Parameter: principal\"", [tname]),
	"Add Definition.TemplateLinked.Principal with the EntityType and EntityId that ?principal stands for",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, tname, slots] in _pf_cedarlib_links
	"?principal" in slots
	tl := _pf_cedarlib_tl(name)
	object.get(tl, "Principal", "__pf_absent") == "__pf_absent"
}
