package cdk_preflight

import rego.v1

_pf_eb_opt_health_streaming_enhanced_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-health-streaming-enhanced", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"HealthStreamingEnabled is true but SystemType is basic; streaming health transitions needs enhanced health reporting",
	"Set SystemType to enhanced or turn HealthStreamingEnabled off", _pf_eb_opt_health_streaming_enhanced_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:cloudwatch:logs:health|HealthStreamingEnabled"
	_pf_eblib_clean(o.rn)
	_pf_eblib_on(o.rn, "aws:elasticbeanstalk:cloudwatch:logs:health|HealthStreamingEnabled")
	_pf_eblib_vals(o.rn, "aws:elasticbeanstalk:healthreporting:system|SystemType") == ["basic"]
}
