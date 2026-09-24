package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-ebs-gp3-iops-min", "ERROR", name,
	"Properties.EBSOptions.Iops",
	sprintf("gp3 starts at 3000 IOPS but the volume asks for %v; CreateDomain answers \"IOPS must be between 3000 and ...\"", [iops]),
	"Raise Iops to 3000 or more (the upper end depends on the instance type)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	_pf_os_opt(name, "EBSOptions", "VolumeType") == "gp3"
	iops := _pf_os_num(_pf_os_opt(name, "EBSOptions", "Iops"))
	iops < 3000
}
