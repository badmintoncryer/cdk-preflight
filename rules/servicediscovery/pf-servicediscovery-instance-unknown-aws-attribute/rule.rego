package cdk_preflight

import rego.v1

# Cloud Map reserves the prefix case-insensitively: aws_my_attr is refused the same
# way AWS_MY_ATTR is, while a lower-case spelling of a known attribute is accepted.
_pf_sduaa_known := {"AWS_ALIAS_DNS_NAME", "AWS_EC2_INSTANCE_ID", "AWS_INIT_HEALTH_STATUS", "AWS_INSTANCE_CNAME", "AWS_INSTANCE_IPV4", "AWS_INSTANCE_IPV6", "AWS_INSTANCE_PORT"}

violation contains make_diag_full("pf-servicediscovery-instance-unknown-aws-attribute", "ERROR", name,
	"Properties.InstanceAttributes",
	sprintf("Instance attribute '%v' uses the reserved AWS_ prefix; RegisterInstance fails with \"Invalid attribute: [%v]. [aws_] prefix is reserved for AWS attributes.\"", [k, k]),
	"Rename the custom attribute so it does not start with AWS_ (the prefix is matched case-insensitively)",
	"https://docs.aws.amazon.com/cloud-map/latest/dg/registering-instances.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	some k, _ in _pf_sd_attrs(name)
	startswith(upper(k), "AWS_")
	not upper(k) in _pf_sduaa_known
}
