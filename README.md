[About](#influxdb2-provision) \| [Usage](#usage)

## Influxdb2 Provision

This is a tiny helper utility that uses influxdb2's python client api to realize
a desired state of organizations, buckets, authentications and users.
All actions are taken out on a best-effort basis. Updating existing entities
may sometimes not be possible due to influxdb's design.

This tool was designed to be used for NixOS and may be changed arbitrarily
at any point in time to accomodate this primary goal.

## Usage

Make sure the influxdb-client python library is installed and run the utility by using

```bash
$ python3 ./influxdb2-provision.py state.json "<URL>" "<ADMIN_TOKEN>"
```

Refer to the influxdb2 nixos module to see what should be contained in `state.json`.
This tool is made for automation and expects pre-sanitized json input.
