package cdk_preflight

import rego.v1

# Ref of an AWS::VerifiedPermissions::PolicyTemplate returns the composite
# <policyStoreId>|<policyTemplateId> (its primaryIdentifier is that pair), and the
# pipe breaks the pattern ^[a-zA-Z0-9-]*$ that the Policy handler enforces on
# Definition.TemplateLinked.PolicyTemplateId. Fn::GetAtt [<id>, PolicyTemplateId]
# returns the bare template id and is the only correct wiring.
#
# resolve() collapses Ref and Fn::GetAtt to the same logical-ID string, so the raw
# preprocessed document is the only place the two forms are still distinguishable:
# {"Ref": "X"} arrives as {"__kind": "resource", "__ref": "X"} and Fn::GetAtt as
# {"__kind": "getatt:<Attr>", "__ref": "X"} (AGENTS.md, measured 2026-09-05).
# An Fn::If keeps a "__conditional" marker instead and is skipped by the __kind
# test, as is a Ref to a parameter or to any type other than a PolicyTemplate.
violation contains make_diag_full("pf-avp-template-linked-id-not-ref", "ERROR", name,
	"Properties.Definition.TemplateLinked.PolicyTemplateId",
	sprintf("PolicyTemplateId is a Ref to policy template %v, but Ref on AWS::VerifiedPermissions::PolicyTemplate returns the composite id <policyStoreId>|<policyTemplateId>; the pipe breaks the property pattern ^[a-zA-Z0-9-]*$ and the deployment fails with \"#/Definition/TemplateLinked/PolicyTemplateId: failed validation constraint for keyword [pattern]\"", [tgt]),
	sprintf("Use Fn::GetAtt [%v, PolicyTemplateId], which returns the bare template id", [tgt]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-verifiedpermissions-policytemplate.html") if {
	some name in resources_of_type("AWS::VerifiedPermissions::Policy")
	props := input.resources[name].properties
	is_object(props)
	d := object.get(props, "Definition", null)
	is_object(d)
	tl := object.get(d, "TemplateLinked", null)
	is_object(tl)
	tid := object.get(tl, "PolicyTemplateId", null)
	is_object(tid)
	object.get(tid, "__kind", null) == "resource"
	tgt := object.get(tid, "__ref", null)
	is_string(tgt)
	tgt in resources_of_type("AWS::VerifiedPermissions::PolicyTemplate")
}
