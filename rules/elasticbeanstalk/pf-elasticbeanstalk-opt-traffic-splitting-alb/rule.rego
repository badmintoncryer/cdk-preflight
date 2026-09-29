package cdk_preflight

import rego.v1

_pf_eb_opt_traffic_splitting_alb_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-traffic-splitting-alb", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("DeploymentPolicy is TrafficSplitting but LoadBalancerType is %s (classic when not set); traffic-splitting deployments only work with an Application Load Balancer", [lb]),
	"Set aws:elasticbeanstalk:environment LoadBalancerType to application, or pick another DeploymentPolicy", _pf_eb_opt_traffic_splitting_alb_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:command|DeploymentPolicy"
	_pf_eblib_clean(o.rn)
	o.s == "TrafficSplitting"
	count(_pf_eblib_vals(o.rn, "aws:elasticbeanstalk:command|DeploymentPolicy")) == 1
	not _pf_eblib_single(o.rn)
	lb := _pf_eblib_lbtype(o.rn)
	lb != "application"
}
