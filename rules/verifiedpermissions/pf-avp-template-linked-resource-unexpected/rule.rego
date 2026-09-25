package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-linked-resource-unexpected", "ERROR", name, "Properties.Definition.TemplateLinked.Resource",
	sprintf("policy template %v declares no ?resource, so supplying Resource is rejected; CreatePolicy answers \"Invalid Parameter: resource\"", [tname]),
	"Drop Definition.TemplateLinked.Resource, or add ?resource to the policy template",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, tname, slots] in _pf_cedarlib_links
	not "?resource" in slots
	tl := _pf_cedarlib_tl(name)
	r := object.get(tl, "Resource", null)
	is_object(r)
	object.get(r, "EntityType", "__pf_absent") != "__pf_absent"
}
