package cdk_preflight

import rego.v1

_pf_cfgase_sources(name) := count([k |
	some k in {"AccountAggregationSources", "OrganizationAggregationSource"}
	_pf_cfglib_present(_pf_cfglib_props(name), k)
])

_pf_cfgase_err := "the aggregator create fails: it aggregates either named accounts or an organization"

violation contains make_diag_full("pf-config-aggregator-source-exactly-one", "ERROR", name,
	"Properties",
	sprintf("the aggregator names %d of AccountAggregationSources / OrganizationAggregationSource; %s", [n, _pf_cfgase_err]),
	"Set exactly one of AccountAggregationSources or OrganizationAggregationSource",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-config-configurationaggregator.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationAggregator")
	n := _pf_cfgase_sources(name)
	n != 1
}
