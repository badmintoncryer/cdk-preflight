package cdk_preflight

import rego.v1

# CFn DBInstance DomainDnsIps: 'Two IP addresses must be provided. If there isn't a secondary domain controller,
# use the IP address of the primary domain controller for both entries in the list.'

violation contains make_diag_full("pf-rds-domain-dns-ips-two", "ERROR", name,
	"Properties.DomainDnsIps",
	"DomainDnsIps must list exactly two IP addresses; repeat the primary domain controller if there is no secondary",
	"List two DNS IP addresses (the same address twice if there is only one domain controller)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	raw := _pf_ll_raw(name, "Properties.DomainDnsIps")
	is_array(raw)
	_pf_countable_list(name, "Properties.DomainDnsIps")
	n := count(raw)
	n > 0
	n != 2
}
