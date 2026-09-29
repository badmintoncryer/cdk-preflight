package cdk_preflight

import rego.v1

_pf_eb_opt_ad_requires_name_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-ad-requires-name", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"DirectoryId is set but DirectoryName is not; the directory ID and its fully qualified DNS name must be set together",
	"Set DirectoryName to the directory's fully qualified domain name", _pf_eb_opt_ad_requires_name_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:windows:activedirectory|DirectoryId"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	not _pf_eblib_filled(o.rn, "aws:elasticbeanstalk:windows:activedirectory|DirectoryName")
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-ad-requires-name", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"DirectoryName is set but DirectoryId is not; the directory ID and its fully qualified DNS name must be set together",
	"Set DirectoryId to the ID of the directory", _pf_eb_opt_ad_requires_name_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:windows:activedirectory|DirectoryName"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	not _pf_eblib_filled(o.rn, "aws:elasticbeanstalk:windows:activedirectory|DirectoryId")
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-ad-requires-name", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	"DirectoryOU is set but DirectoryId is not; the organizational unit only applies to a directory that is being joined",
	"Set DirectoryId (and DirectoryName), or remove DirectoryOU", _pf_eb_opt_ad_requires_name_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:windows:activedirectory|DirectoryOU"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	not _pf_eblib_filled(o.rn, "aws:elasticbeanstalk:windows:activedirectory|DirectoryId")
}
