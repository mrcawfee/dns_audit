# Description
This program is an uncessarily complicated way to monitor multiple domains authoratative DNS as well
as IP addresses and spits out a report.

# Requirements
Rust 1.69+

cargo build

# Usage

| Name | Description | 
| ---- | ----------- | 
| --root-zone file | zonefile downloaded from https://www.internic.net/domain/root.zone |
| -c file | JSON file that contains the monitoring input, use '-' for stdin |
| -o file | write json file with results, '-' for stdout. By default only failures are written, all can be used with --all |
| --cache-in file | use the root nameserver cache file that was previously created |
| --cache-out file | write the root nameserver performance cache, for input with cache-in |
| --all | write all results, not just the errors |
| -w # | check every # seconds continously, program will exit upon any error |

## First run
For your first run you are going to want to test the root nameservers to determine which is fastest, this
becomes more useful as your dataset increases

Download the root zone file from Iana, https://www.internic.net/domain/root.zone

```
./dns_audit --root-zone root.zone --cache-out cache.json
Testing Root Nameservers... Complete
Nothing to Test
```

## Input Format

The input format is a JSON document with the following properties

```
[
	{
		"domain_name": "google.com",
		"ns": [ "ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com" ],
		"ip": [ "142.250.176.78", "2607:f8b0:4023:1004::64", "2607:f8b0:4023:1004::65", "2607:f8b0:4023:1004::66", "2607:f8b0:4023:1004::74" ]
	},
	{
		"domain_name": "domain2.."
		...
	}
]
```

| Name | Description |
| ---- | ----------- |
| domain_name | It's the domain name wierdo |
| ns | array of the authoratative nameservesr to expect, can be null to bypass this check |
| ip | array of ipv4 and v6 addresses to expect, can be null to bypass check |

## Running a Test

```
./dns_audit --root-zone root.zone --cache-in root.json -c input.json -o -
[{"domain_name":"google.com","success":false,"reason":["did not return the correct ips"],"flags":["ResolveIpNotMatch"],"nameservers":["ns2.google.com.","ns1.google.com.","ns3.google.com.","ns4.google.com."],"ips":["142.250.68.78"]}]

```

## Return Code

Exits with 0 if ok, 2 if a test was ran and was not successful, 1 for all other problems.

