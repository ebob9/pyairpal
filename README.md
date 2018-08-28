# PyAirpal
Python Client/SDK for Airpal

## Synopsis

PyAirPal: Python Client/SDK to allow headless queries and response retrieval for Airpal.

## Code Example

View the included example.py

## Motivation

Airpal (http://airbnb.io/airpal/) is a great WebUI/Front end for PrestoDB (https://prestodb.io/)

One really nice thing Airpal does is create a method of User Access Control/logging/etc to the PrestoDB interface.

Native PrestoDB clients will likely be more efficient, but this stack allows organizations to provide batch/scripting 
access to the PrestoDB Via Airpal, while maintaining the nice UAC/etc that Airpal provides.

## Requirements

* Working Airpal server
* Python modules:
    * Requests - http://docs.python-requests.org/en/master/
    * SSEClient - https://pypi.python.org/pypi/sseclient
    * Pandas (for example script only) - http://pandas.pydata.org/

## License

MIT

## Version
Version | Changes
------- | --------
**1.1.3**| Update yield_csv() to allow for raw requests response.
**1.1.2**| Fix issue #1, update logging to best practice, Handling exception while loading next_event() to json #4
**1.1.1**| Python3 support, Remove PANDAS dependency, fix issue #1
**1.0.2**| Fix for missing requirements in PIP support
**1.0.1**| PIP support
**1.0.0**| Initial Release
