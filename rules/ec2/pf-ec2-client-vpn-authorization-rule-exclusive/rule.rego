package cdk_preflight

import rego.v1

_pf_cvpnare_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

# Both properties are optional in the schema, so nothing rejects setting both;
# EC2 refuses the pair at create time.
violation contains make_diag_full("pf-ec2-client-vpn-authorization-rule-exclusive", "ERROR", name,
	"Properties.AccessGroupId",
	"AccessGroupId and AuthorizeAllGroups are mutually exclusive (\"You can specify either access-group-id or authorize-all-groups, not both\")",
	"Drop AccessGroupId, or set AuthorizeAllGroups to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-clientvpnauthorizationrule.html") if {
	some name in resources_of_type("AWS::EC2::ClientVpnAuthorizationRule")
	resolve(name, "Properties.AuthorizeAllGroups") == true
	not _pf_cvpnare_absent(name, "AccessGroupId")
}
