package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-az-count-valid", "ERROR", name,
	"Properties.ClusterConfig.ZoneAwarenessConfig.AvailabilityZoneCount",
	sprintf("AvailabilityZoneCount %v is not supported; CreateDomain answers \"NumberOfAvailabilityZones should be either 2 or 3\"", [az]),
	"Use 2 or 3 Availability Zones",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-zoneawarenessconfig.html") if {
	some name in _pf_os_domains
	az := _pf_os_num(_pf_os_opt3(name, "ClusterConfig", "ZoneAwarenessConfig", "AvailabilityZoneCount"))
	not az in {2, 3}
}
