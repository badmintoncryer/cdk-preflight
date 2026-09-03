package cdk_preflight

import rego.v1

_pf_ec2sse_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html"

# The member sets come verbatim from the EC2 error messages.
_pf_ec2sse_sets := {"in": ["CidrIp", "CidrIpv6", "SourceSecurityGroupId", "SourcePrefixListId"], "out": ["CidrIp", "CidrIpv6", "DestinationPrefixListId", "DestinationSecurityGroupId"]}

_pf_ec2sse_dirkey := {"SecurityGroupIngress": "in", "SecurityGroupEgress": "out"}

_pf_ec2sse_rkey := {"AWS::EC2::SecurityGroupIngress": "in", "AWS::EC2::SecurityGroupEgress": "out"}

_pf_ec2sse_count(entry, setkey) := n if {
	is_object(entry)
	n := count([k | some k in _pf_ec2sse_sets[setkey]; object.get(entry, k, "__pf_absent") != "__pf_absent"])
}

# Embedded rules: two or more members is an error; zero is tolerated
# (a source-less embedded ingress deployed clean on 2026-09-03).
violation contains make_diag_full("pf-ec2-sg-source-exclusive", "ERROR", name,
	sprintf("Properties.%s.%d", [dir, item.index]),
	sprintf("The rule sets %v of %v; EC2 allows only one (\"Only one of %s can be specified\")", [n, _pf_ec2sse_sets[k], concat(", ", _pf_ec2sse_sets[k])]),
	"Keep exactly one source/destination field on the rule",
	_pf_ec2sse_url) if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	some dir in {"SecurityGroupIngress", "SecurityGroupEgress"}
	some item in flatten_list(name, sprintf("Properties.%s", [dir]))
	k := _pf_ec2sse_dirkey[dir]
	n := _pf_ec2sse_count(item.value, k)
	n >= 2
}

violation contains make_diag_full("pf-ec2-sg-source-exclusive", "ERROR", name,
	"Properties",
	sprintf("The rule sets %v of %v; EC2 requires exactly one (\"Exactly one of %s must be specified and not empty\")", [n, _pf_ec2sse_sets[k], concat(", ", _pf_ec2sse_sets[k])]),
	"Set exactly one source/destination field on the rule resource",
	_pf_ec2sse_url) if {
	some rtype in {"AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}
	some name in resources_of_type(rtype)
	k := _pf_ec2sse_rkey[rtype]
	n := _pf_ec2sse_count(input.resources[name].properties, k)
	n != 1
}
