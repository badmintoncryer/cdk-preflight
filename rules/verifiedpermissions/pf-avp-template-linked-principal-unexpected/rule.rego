package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-linked-principal-unexpected", "ERROR", name, "Properties.Definition.TemplateLinked.Principal",
	sprintf("policy template %v declares no ?principal, so supplying Principal is rejected; CreatePolicy answers \"Invalid Parameter: principal\"", [tname]),
	"Drop Definition.TemplateLinked.Principal, or add ?principal to the policy template",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, tname, slots] in _pf_cedarlib_links
	not "?principal" in slots
	tl := _pf_cedarlib_tl(name)
	p := object.get(tl, "Principal", null)
	is_object(p)
	object.get(p, "EntityType", "__pf_absent") != "__pf_absent"
}
