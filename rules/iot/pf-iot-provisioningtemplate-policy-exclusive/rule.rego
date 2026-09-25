package cdk_preflight

import rego.v1

# Inside the JSON body, the provisioning template has its own resource types.
# The policy one is exclusive: one of the two properties, never both.
violation contains make_diag_full("pf-iot-provisioningtemplate-policy-exclusive", "ERROR", name,
	sprintf("Properties.TemplateBody.Resources.%s", [rname]),
	sprintf("the provisioning template's policy resource '%s' sets both PolicyName and PolicyDocument; CreateProvisioningTemplate answers \"The template body is invalid: Policy resources must define one property: PolicyName or PolicyDocument\"", [rname]),
	"Name an existing policy or inline a document, not both",
	"https://docs.aws.amazon.com/iot/latest/developerguide/provision-template.html#policy-resources") if {
	some name in resources_of_type("AWS::IoT::ProvisioningTemplate")
	body := _pf_iotlib_template_body(name)
	some rname, r in object.get(body, "Resources", {})
	is_object(r)
	object.get(r, "Type", "") == "AWS::IoT::Policy"
	p := object.get(r, "Properties", {})
	is_object(p)
	object.get(p, "PolicyName", "__pf_absent") != "__pf_absent"
	object.get(p, "PolicyDocument", "__pf_absent") != "__pf_absent"
}
