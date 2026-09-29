package cdk_preflight

import rego.v1

_pf_eb_tmpl_source_required_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CreateConfigurationTemplate.html"

violation contains make_diag_full("pf-elasticbeanstalk-tmpl-source-required", "ERROR", name, "Properties",
	"The ConfigurationTemplate has none of SourceConfiguration, SolutionStackName, PlatformArn or EnvironmentId; CreateConfigurationTemplate rejects a template that has no source to start from",
	"Set PlatformArn (or SolutionStackName), SourceConfiguration or EnvironmentId", _pf_eb_tmpl_source_required_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ConfigurationTemplate")
	p := _pf_eblib_props(name)
	object.get(p, "SourceConfiguration", "__pf_absent") == "__pf_absent"
	object.get(p, "SolutionStackName", "__pf_absent") == "__pf_absent"
	object.get(p, "PlatformArn", "__pf_absent") == "__pf_absent"
	object.get(p, "EnvironmentId", "__pf_absent") == "__pf_absent"
}
