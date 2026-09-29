package cdk_preflight

import rego.v1

_pf_eb_opt_ad_windows_only_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-ad-windows-only", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Option %s is set but the PlatformArn is not a Windows Server platform (%s); the Active Directory options only exist on Windows Server platforms", [o.ns, arn]),
	"Remove the aws:elasticbeanstalk:windows:activedirectory options or use a Windows Server platform", _pf_eb_opt_ad_windows_only_url) if {
	o := _pf_eblib_opt[_]
	o.ns == "aws:elasticbeanstalk:windows:activedirectory"
	arn := _pf_eblib_props(o.rn).PlatformArn
	is_string(arn)
	regex.match(`^arn:aws[a-z-]*:elasticbeanstalk:[a-z0-9-]+::platform/`, arn)
	not contains(lower(arn), "windows")
	o.i == min({x.i | x := _pf_eblib_opt[_]; x.rn == o.rn; x.ns == "aws:elasticbeanstalk:windows:activedirectory"})
}
