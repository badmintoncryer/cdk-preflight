package cdk_preflight

import rego.v1

_pf_rssport_out(n) if n < 5431

_pf_rssport_out(n) if {
	n > 5455
	n < 8191
}

_pf_rssport_out(n) if n > 8215

violation contains make_diag_full("pf-redshiftserverless-port-range", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v is outside 5431-5455 and 8191-8215; CreateWorkgroup fails with \"Amazon Redshift Serverless doesn't support ports outside of the range (5431-5455) and (8191-8215): 5430.\"", [n]),
	"Pick a port between 5431 and 5455 or between 8191 and 8215 (the default is 5439)",
	"https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateWorkgroup.html") if {
	some name in resources_of_type("AWS::RedshiftServerless::Workgroup")
	n := to_number(resolve(name, "Properties.Port"))
	_pf_rssport_out(n)
}
