package cdk_preflight

import rego.v1

_pf_cfgare_err := "the aggregator create fails: the two ways of naming Regions contradict each other"

violation contains make_diag_full("pf-config-aggregator-account-source-regions-exclusive", "ERROR", name,
	sprintf("Properties.AccountAggregationSources[%d]", [s.index]),
	sprintf("the account source sets AllAwsRegions together with %d named Region(s); %s", [count(regions), _pf_cfgare_err]),
	"Set AllAwsRegions: true, or list AwsRegions - not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationaggregator-accountaggregationsource.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationAggregator")
	some s in flatten_list(name, "Properties.AccountAggregationSources")
	object.get(s.value, "AllAwsRegions", false) == true
	regions := _pf_cfglib_list(s.value, "AwsRegions")
	count(regions) > 0
}
