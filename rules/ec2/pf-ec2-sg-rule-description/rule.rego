package cdk_preflight

import rego.v1

_pf_sgdesc_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html"

_pf_sgdesc_pat := `^[a-zA-Z0-9._ :/()#,@\[\]+=&;{}!$*-]{0,255}$`

# inline rule lists on a security group
_pf_sgdesc_bad contains [name, path, desc] if {
	some n in resources_of_type("AWS::EC2::SecurityGroup")
	some key in ["SecurityGroupIngress", "SecurityGroupEgress"]
	some r in flatten_list(n, sprintf("Properties.%s", [key]))
	is_object(r.value)
	desc := object.get(r.value, "Description", null)
	is_string(desc)
	not regex.match(_pf_sgdesc_pat, desc)
	name := n
	path := sprintf("Properties.%s.%d.Description", [key, r.index])
}

# standalone rule resources
_pf_sgdesc_bad contains [name, path, desc] if {
	some t in ["AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"]
	some n in resources_of_type(t)
	desc := resolve(n, "Properties.Description")
	is_string(desc)
	not regex.match(_pf_sgdesc_pat, desc)
	name := n
	path := "Properties.Description"
}

violation contains make_diag_full("pf-ec2-sg-rule-description", "ERROR", name,
	path,
	sprintf("Security group rule description '%s' is rejected: EC2 allows fewer than 256 characters from the set a-zA-Z0-9. _-:/()#,@[]+=&;{}!$* (non-ASCII text such as Japanese is rejected)", [desc]),
	"Write the rule description in the allowed ASCII set and keep it under 256 characters",
	_pf_sgdesc_url) if {
	some [name, path, desc] in _pf_sgdesc_bad
}
