package cdk_preflight

import rego.v1

# Fn::GetAZs is already caught by the engine (F6101), but a GetAtt that returns
# a list is not: the engine keeps it as an unresolved marker and cannot tell the
# attribute's return type. This carries the handful of list-returning attributes
# that show up in real templates and deliberately under-detects the rest.
_pf_cfnexplist_attrs := {
	"AWS::AmazonMQ::Broker": {"AmqpEndpoints", "HttpEndpoints", "IpAddresses", "MqttEndpoints", "OpenWireEndpoints", "StompEndpoints", "WssEndpoints"},
	"AWS::EC2::NetworkInterface": {"SecondaryPrivateIpAddresses"},
	"AWS::EC2::Subnet": {"Ipv6CidrBlocks"},
	"AWS::EC2::VPC": {"CidrBlockAssociations", "Ipv6CidrBlocks"},
	"AWS::ElasticLoadBalancingV2::LoadBalancer": {"SecurityGroups"},
	"AWS::Route53::HostedZone": {"NameServers"},
}

_pf_cfnexplist_bad contains [out, ref, attr] if {
	some out, o in input.outputs
	object.get(o, "exportName", null) != null
	v := object.get(o, "value", null)
	is_object(v)
	kind := object.get(v, "__kind", "")
	startswith(kind, "getatt:")
	attr := substring(kind, 7, -1)
	ref := object.get(v, "__ref", "")
	rtype := object.get(object.get(input.resources, ref, {}), "resourceType", "")
	attr in object.get(_pf_cfnexplist_attrs, rtype, set())
}

violation contains make_diag_full("pf-cfn-export-value-list", "ERROR", out,
	sprintf("Outputs.%s.Value", [out]),
	sprintf("This output exports Fn::GetAtt %s.%s, which returns a list; CloudFormation fails the stack with \"Template format error: Every Value member must be a string.\"", [ref, attr]),
	"Export a single string - wrap the list in Fn::Join, or Fn::Select one element out of it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html") if {
	some [out, ref, attr] in _pf_cfnexplist_bad
}
