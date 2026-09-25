package cdk_preflight

import rego.v1

# A collection with no EncryptionConfig of its own is created only if some
# encryption policy already matches its name. The rule fires only when the
# template itself declares encryption policies and none of their patterns
# reaches this collection - a typo in the pattern - because a template that
# declares none is the normal case where the policy was created out of band.

violation contains make_diag_full("pf-aoss-collection-encryption-policy-mismatch", "ERROR", cname,
	"Properties.Name",
	sprintf("no encryption policy in this template matches collection %v, and the collection sets no EncryptionConfig; CreateCollection answers \"No matching security policy of encryption type found for collection name: %v. Please create security policy of encryption type for this collection.\"", [cn, cn]),
	"Widen the encryption policy Resource pattern to cover the collection name, or give the collection its own EncryptionConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchserverless-collection.html") if {
	some cname in resources_of_type("AWS::OpenSearchServerless::Collection")
	object.get(_pf_aoss_props(cname), "EncryptionConfig", "__pf_absent") == "__pf_absent"
	cn := resolve(cname, "Properties.Name")
	is_string(cn)
	_pf_aoss_enc != set()
	matched := {res |
		some pname in _pf_aoss_enc
		some res in _pf_aoss_resource_set(pname)
		_pf_aoss_covers(res, cn)
	}
	count(matched) == 0
}
