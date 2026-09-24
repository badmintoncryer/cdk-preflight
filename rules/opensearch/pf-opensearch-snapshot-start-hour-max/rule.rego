package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-snapshot-start-hour-max", "ERROR", name,
	"Properties.SnapshotOptions.AutomatedSnapshotStartHour",
	sprintf("AutomatedSnapshotStartHour %v is past midnight; CreateDomain answers \"is not a valid hour of the day. Please specify a number between 0 and 23.\"", [h]),
	"Use an hour between 0 and 23 (UTC)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-snapshotoptions.html") if {
	some name in _pf_os_domains
	h := _pf_os_num(_pf_os_opt(name, "SnapshotOptions", "AutomatedSnapshotStartHour"))
	h > 23
}
