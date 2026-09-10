package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kms-keyspec", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("the key signing key points at %s, which is %s / %s; Route 53 DNSSEC needs ECC_NIST_P256 with KeyUsage SIGN_VERIFY", [k, ks, ku]),
	"Create the KMS key with KeySpec ECC_NIST_P256 and KeyUsage SIGN_VERIFY",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	k := _pf_r53z_key_of(name)
	p := _pf_r53z_props(k)
	ks := object.get(p, "KeySpec", "SYMMETRIC_DEFAULT")
	is_string(ks)
	ku := object.get(p, "KeyUsage", "ENCRYPT_DECRYPT")
	is_string(ku)
	not _pf_r53z_dnssec_keyspec(ks, ku)
}
