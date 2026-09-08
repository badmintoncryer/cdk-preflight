package cdk_preflight

import rego.v1

# Egress defaults to false, so an absent property takes the ingress table.
_pf_ec2nre_egress(n) := e if {
	e := coerce_to_bool(resolve(n, "Properties.Egress"))
}

_pf_ec2nre_egress(n) := false if _pf_ec2lib_absent(n, "Egress")

_pf_ec2nre_key(n) := [acl, eg, num] if {
	acl := resolve(n, "Properties.NetworkAclId")
	is_string(acl)
	eg := _pf_ec2nre_egress(n)
	num := to_number(resolve(n, "Properties.RuleNumber"))
}

_pf_ec2nre_peers(k) := {n |
	some n in resources_of_type("AWS::EC2::NetworkAclEntry")
	_pf_ec2nre_key(n) == k
}

violation contains make_diag_full("pf-ec2-nacl-rule-number-unique", "ERROR", name,
	"Properties.RuleNumber",
	sprintf("Rule number %v is already taken on this network ACL in the same direction by '%s' (\"The network acl entry identified by %v already exists.\")", [k[2], min(peers), k[2]]),
	"Give each entry its own rule number within a direction; the ingress and egress tables are numbered separately",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkaclentry.html") if {
	some name in resources_of_type("AWS::EC2::NetworkAclEntry")
	k := _pf_ec2nre_key(name)
	peers := _pf_ec2nre_peers(k)
	count(peers) > 1
	name != min(peers)
}
