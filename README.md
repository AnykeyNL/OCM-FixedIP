# OCM-FixedIP
Set fixed IPs for Oracle Cloud Migration Service

With this tool you can query each VM's original IP address and set the same IP in the migration plan for the oracle Cloud Migration Service.

The easiest is to run this script from the OCI Cloud Shell with the option -dt (Delegation token).

usage: 

fixip.py -dt -target_id TARGETOCID -fixip

or

fixip.py -dt -migration_id MIGRATIONPLANOCID -fixip


