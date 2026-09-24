package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-ebs-gp3-throughput-min", "ERROR", name,
	"Properties.EBSOptions.Throughput",
	sprintf("gp3 starts at 125 MiB/s but the volume asks for %v; CreateDomain answers \"Throughput must be between 125 and ...\"", [tp]),
	"Raise Throughput to 125 or more (the upper end depends on the instance type)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-ebsoptions.html") if {
	some name in _pf_os_domains
	_pf_os_opt(name, "EBSOptions", "VolumeType") == "gp3"
	tp := _pf_os_num(_pf_os_opt(name, "EBSOptions", "Throughput"))
	tp < 125
}
