package cdk_preflight

import rego.v1

_pf_eb_opt_ad_directory_id_format_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-ad-directory-id-format", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("DirectoryId '%s' is not a directory ID; it must be d- followed by 10 lowercase hexadecimal characters (for example d-1234567890)", [o.s]),
	"Use the directory ID from AWS Directory Service, d- plus 10 hexadecimal characters", _pf_eb_opt_ad_directory_id_format_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elasticbeanstalk:windows:activedirectory|DirectoryId"
	not regex.match(`^d-[0-9a-f]{10}$`, o.s)
}
