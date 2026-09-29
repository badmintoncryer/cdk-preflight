package cdk_preflight

import rego.v1

_pf_eb_opt_elbv2_listener_cert_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-listener-cert", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Listener %s uses Protocol HTTPS but SSLCertificateArns is not set; a secure Application Load Balancer listener needs a certificate", [o.ns]),
	"Set SSLCertificateArns on the listener to an ACM certificate ARN", _pf_eb_opt_elbv2_listener_cert_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "Protocol"
	regex.match(`^aws:elbv2:listener:[^:]+$`, o.ns)
	o.s == "HTTPS"
	_pf_eblib_clean(o.rn)
	_pf_eblib_standalone(o.rn)
	count(_pf_eblib_nsvals(o.rn, o.ns, "Protocol")) == 1
	_pf_eblib_lbtype(o.rn) == "application"
	not _pf_eblib_shared(o.rn)
	not _pf_eblib_nsfilled(o.rn, o.ns, "SSLCertificateArns")
}
