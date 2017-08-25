#!/usr/bin/env python
"""
Example PyAirpal client
Extremely basic - does not verify login/query were successful.
"""

import pyairpal
import pandas
import json
import sys

# #uncomment for debug
# import logging
# logging.basicConfig()
# clilogger = logging.getLogger()
# clilogger.setLevel(logging.DEBUG)

# Create Connection Constructor Object
AirpalConnection = pyairpal.Airpal('http://localhost:8081/')

# Login to Airpal
print("Logging in..")
AirpalConnection.login("myusername", "mypassword")

# After login, subscribe to event_stream to get status of submissions.
event_stream = AirpalConnection.subscribe()

# execute PrestoDB-SQL query
print("Executing Query..")
status, response = AirpalConnection.execute("""
SHOW TABLES
""")

# Extract UUID from query execution response.
uuid = response.json().get('uuid')

if uuid:
    # extract the final event if UUID was in response. Also, print status as we wait.
    print("Waiting for Query..")
    final_event = AirpalConnection.wait_for_job(uuid, print_status=True)
else:
    print "Error, no UUID in response: {0}".format(response.txt)
    final_event = {}
    sys.exit(1)

# Get the state of the final event
state = final_event.get('state')


if state == "FAILED":
    # Query failed, print info
    print "Job Failed: {0}".format(json.dumps(final_event.get('error', '{"message": "No Error info returned."}'),
                                              indent=4))
    sys.exit(1)

else:
    # success, dive to location to extract the CSV result location
    location = final_event.get('output', {}).get('location')
    if not location:
        print "Error, no location URL: {0}".format(json.dumps(final_event, indent=4))
        sys.exit(1)

    # grab data and dump it into DataFrame
    pd = pandas.read_csv(AirpalConnection.yield_csv(location, fd=True))

    # simply print DataFrame for example
    print("DataFrame Output")
    print(pd)

# Cleanup
AirpalConnection.logout()
