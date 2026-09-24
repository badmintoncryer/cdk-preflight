package cdk_preflight

import rego.v1

# スキーマは許容値の一覧を持たない（Required: Yes の素の文字列）。
violation contains make_diag_full("pf-ses-contact-list-topic-subscription-status-enum", "ERROR", name,
	"Properties.Topics",
	sprintf("DefaultSubscriptionStatus '%v' is not a subscription status; the contact list create fails with \"Value at 'topics.N.member.defaultSubscriptionStatus' failed to satisfy constraint: Member must satisfy enum value set: [OPT_OUT, OPT_IN]\"", [s]),
	"Use OPT_IN or OPT_OUT",
	"https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateContactList.html") if {
	some name in resources_of_type("AWS::SES::ContactList")
	some item in flatten_list(name, "Properties.Topics")
	t := item.value
	is_object(t)
	s := object.get(t, "DefaultSubscriptionStatus", null)
	_pf_ses_lit(s)
	not s in {"OPT_IN", "OPT_OUT"}
}
