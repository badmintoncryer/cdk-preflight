package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-zone-awareness-config-requires-enabled", "ERROR", name,
	"Properties.ClusterConfig.ZoneAwarenessConfig",
	"ZoneAwarenessConfig is set while ZoneAwarenessEnabled is not true; CreateDomain answers \"ZoneAwarenessEnabled must be set to True to specify the ZoneAwarenessSettings\"",
	"Set ClusterConfig.ZoneAwarenessEnabled to true, or drop ZoneAwarenessConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-zoneawarenessconfig.html") if {
	some name in _pf_os_domains
	_pf_os_has2(name, "ClusterConfig", "ZoneAwarenessConfig")
	not _pf_os_on(name, "ClusterConfig", "ZoneAwarenessEnabled")
}
