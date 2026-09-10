package cdk_preflight

import rego.v1

# One shared helper: every destination that takes inline credentials also
# accepts a Secrets Manager configuration instead.
_pf_fhcred_secret(c) if {
	s := object.get(c, "SecretsManagerConfiguration", null)
	is_object(s)
	coerce_to_bool(object.get(s, "Enabled", false)) == true
}

violation contains make_diag_full("pf-firehose-redshift-credentials", "ERROR", name,
	"Properties.RedshiftDestinationConfiguration.Password",
	"Password is not set and no Secrets Manager configuration is enabled; the stream create fails with \"Redshift Database Password is required for Redshift Destination\"",
	"Set Username and Password, or enable SecretsManagerConfiguration with a SecretARN",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_RedshiftDestinationConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.RedshiftDestinationConfiguration"
	object.get(c, "Password", "__pf_absent") == "__pf_absent"
	not _pf_fhcred_secret(c)
}
