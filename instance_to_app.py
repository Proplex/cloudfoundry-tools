import subprocess
import os
import sys
import json
import time

# We need the BOSH deployment name for TAS/CF because we're going to SSH into a Diego cell later on
if os.environ.get("CF_DEPLOYMENT") is None:
    print("You need to set the environment variable 'CF_DEPLOYMENT' to the BOSH deployment name of CF.")
    sys.exit(1)

if os.environ.get("BOSH_ENVIRONMENT") is None:
    print("You need to set the BOSH director environment variables such as 'BOSH_ENVIRONMENT', 'BOSH_CLIENT', 'BOSH_CLIENT_SECRET', and 'BOSH_CA_CERT'")
    sys.exit(1)

#subprocess.run(["bosh", "deps", "--json"], capture_output=True)

# Get the cfdot output from a Diego cell. This rube goldberg-esque approach is required because Diego doesn't expose this data freely,
# and cfdot is the only way we can (easily) get access to it.
print("Grabbing LRP data from BBS...")
subprocess.run(["bosh", "ssh", "-d", f"{os.environ.get('CF_DEPLOYMENT')}", "diego_cell/0",
               "-c", "source /var/vcap/jobs/cfdot/bin/setup && cfdot actual-lrps | jq -s > /tmp/cfdot-output.json"])
subprocess.run(["bosh", "scp", "-d", f"{os.environ.get('CF_DEPLOYMENT')}",
               "diego_cell/0:/tmp/cfdot-output.json", "/tmp/cfdot-output.json"])

# Create a CSV file with all the data we need to import into whatever Excel thingamabob we want to use.
print("Collating data...")
mapped_apps = ["instance_guid,app_guid,app_name,org_name,space_name"]
# Parse data from BBS
with open("/tmp/cfdot-output.json", 'r') as lrp_data_raw:
    lrp_data = json.load(lrp_data_raw)
    for app in lrp_data:
        if app['state'] is "RUNNING":
            mapped_apps.append(
                f"{app['instance_guid']},{app['metric_tags']['app_id']},{app['metric_tags']['app_name']},{app['metric_tags']['organization_name']},{app['metric_tags']['space_name']}")
        else:
            print(f"App with process GUID {app['process_guid']} is crashed; cannot get information. Skipping.")

# Write to disk
with open(f"instance_guid_report_{time.strftime('%Y-%m-%d_at_%H-%M-%S')}.csv", 'w') as csv_file:
    for app in mapped_apps:
        csv_file.write(f"{app}\n")
print("Complete.")

# How I feel right now: https://www.youtube.com/watch?v=y8OnoxKotPQ
