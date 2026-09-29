package cdk_preflight

import rego.v1

_pf_eb_opt_rootvolume_size_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-size", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeSize is %v GB, which is below the accepted range of 8 to 16384 GB; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeSize in the range 8 to 16384", _pf_eb_opt_rootvolume_size_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeSize"
	n := _pf_eblib_num(o.s)
	n < 8
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-size", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeSize is %v GB, which is above the accepted range of 8 to 16384 GB; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeSize in the range 8 to 16384", _pf_eb_opt_rootvolume_size_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeSize"
	n := _pf_eblib_num(o.s)
	n > 16384
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-size", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeSize is %v GB, which is above (for RootVolumeType standard) the accepted range of 8 to 1024 GB; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeSize in the range 8 to 1024", _pf_eb_opt_rootvolume_size_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeSize"
	n := _pf_eblib_num(o.s)
	_pf_eblib_clean(o.rn)
	_pf_eblib_vals(o.rn, "aws:autoscaling:launchconfiguration|RootVolumeType") == ["standard"]
	n > 1024
}
