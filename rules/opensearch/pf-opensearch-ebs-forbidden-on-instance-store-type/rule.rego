package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-ebs-forbidden-on-instance-store-type", "ERROR", name,
	"Properties.EBSOptions.EBSEnabled",
	sprintf("%v is an instance-store instance type; CreateDomain answers \"Instance type %v does not support EBS storage\"", [t, t]),
	"Drop EBSOptions for this instance type, or pick a family that supports EBS (for example m6g / r6g / t3)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "EBSOptions", "EBSEnabled")
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) in _pf_os_instance_store_families
}
