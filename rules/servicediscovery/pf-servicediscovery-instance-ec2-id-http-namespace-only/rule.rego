package cdk_preflight

import rego.v1

# Two hops: instance -> service -> namespace. Written positively, so a literal
# ns-xxxx (whose target is not in this template) leaves the rule silent.
violation contains make_diag_full("pf-servicediscovery-instance-ec2-id-http-namespace-only", "ERROR", name,
	"Properties.InstanceAttributes.AWS_EC2_INSTANCE_ID",
	sprintf("Service '%v' lives in DNS namespace '%v', so AWS_EC2_INSTANCE_ID cannot be used; RegisterInstance fails with \"AWS_EC2_INSTANCE_ID provided in namespace type DNS_PUBLIC. It is only supported in HTTP namespace\"", [svc, ns]),
	"Register the instance in a service of an AWS::ServiceDiscovery::HttpNamespace, or supply AWS_INSTANCE_IPV4/IPV6 instead",
	"https://docs.aws.amazon.com/cloud-map/latest/dg/registering-instances.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	svc := _pf_sd_inst_svc(name)
	_pf_sd_has_attr(name, "AWS_EC2_INSTANCE_ID")
	some ns in _pf_sd_ns_ids(svc)
	ns in _pf_sd_dns_namespaces
}
