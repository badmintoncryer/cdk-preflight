package cdk_preflight

import rego.v1

_pf_eb_opt_rootvolume_iops_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-iops", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeIOPS is %v, which is below the accepted range of 100 to 20000; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeIOPS in the range 100 to 20000", _pf_eb_opt_rootvolume_iops_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeIOPS"
	n := _pf_eblib_num(o.s)
	n < 100
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-iops", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeIOPS is %v, which is above the accepted range of 100 to 20000; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeIOPS in the range 100 to 20000", _pf_eb_opt_rootvolume_iops_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeIOPS"
	n := _pf_eblib_num(o.s)
	n > 20000
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-iops", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeIOPS is %v, which is below (for RootVolumeType gp3) the accepted range of 3000 to 16000; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeIOPS in the range 3000 to 16000", _pf_eb_opt_rootvolume_iops_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeIOPS"
	n := _pf_eblib_num(o.s)
	_pf_eblib_clean(o.rn)
	_pf_eblib_vals(o.rn, "aws:autoscaling:launchconfiguration|RootVolumeType") == ["gp3"]
	n < 3000
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-rootvolume-iops", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("RootVolumeIOPS is %v, which is above (for RootVolumeType gp3) the accepted range of 3000 to 16000; Elastic Beanstalk rejects the setting", [n]),
	"Use a RootVolumeIOPS in the range 3000 to 16000", _pf_eb_opt_rootvolume_iops_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:autoscaling:launchconfiguration|RootVolumeIOPS"
	n := _pf_eblib_num(o.s)
	_pf_eblib_clean(o.rn)
	_pf_eblib_vals(o.rn, "aws:autoscaling:launchconfiguration|RootVolumeType") == ["gp3"]
	n > 16000
}
