package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-ebs-io1-iops-min", "ERROR", name,
	"Properties.EBSOptions.Iops",
	sprintf("io1 starts at 1000 IOPS but the volume asks for %v; CreateDomain answers \"Iops must be between 1000 and ...\"", [iops]),
	"Raise Iops to 1000 or more (the upper end depends on the instance type)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	_pf_os_opt(name, "EBSOptions", "VolumeType") == "io1"
	iops := _pf_os_num(_pf_os_opt(name, "EBSOptions", "Iops"))
	iops < 1000
}
