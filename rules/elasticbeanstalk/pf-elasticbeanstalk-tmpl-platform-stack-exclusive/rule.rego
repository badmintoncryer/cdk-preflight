package cdk_preflight

import rego.v1

_pf_eb_tmpl_platform_stack_exclusive_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CreateConfigurationTemplate.html"

violation contains make_diag_full("pf-elasticbeanstalk-tmpl-platform-stack-exclusive", "ERROR", name, "Properties.SolutionStackName",
	"PlatformArn and SolutionStackName are both set; CreateConfigurationTemplate takes one or the other and rejects the pair",
	"Keep PlatformArn (versioned) or SolutionStackName, not both", _pf_eb_tmpl_platform_stack_exclusive_url) if {
	some name in resources_of_type("AWS::ElasticBeanstalk::ConfigurationTemplate")
	p := _pf_eblib_props(name)
	is_string(p.PlatformArn)
	is_string(p.SolutionStackName)
}
