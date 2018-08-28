#!/usr/bin/env python
"""
Python Client/SDK for querying AirPal for headless statistics.

Airpal provides user access control and management for PrestoDB. This client was created to allow a scriptable client
interface to Airpal, so that automated queries can have the same UAC as interactive data mining.
"""

import requests
from requests.packages import urllib3
import sseclient
import json
import logging
import io
from time import sleep

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

__author__ = "Aaron Edwards <pyairpal@ebob9.com>"
__email__ = "pyairpal@ebob9.com"

# Set logging to function name
logger = logging.getLogger(__name__)
# Get logging level, use this to bypass logging functions if not set. (Issue #1)
logger_level = logger.getEffectiveLevel()


class Airpal(object):
    """
    Class for interacting with AirPal.
    """

    # basic init vars
    __ap_server = ""
    __ap_port = ""
    __ap_scheme = ""
    __ap_verifyssl = True

    # user info
    __ap_user = ""
    __ap_pass = ""

    # rest call
    __http_session = ""

    def __init__(self, airpal_url="http://localhost:8081", verifyssl=True):
        """
        Parse the basic URL for Airpal on Constructor Creation
        :param airpal_url: URL to AirPal Server
        """
        try:
            parsed_url = urlparse.urlparse(str(airpal_url))
            self.__ap_server = parsed_url.hostname
            self.__ap_port = parsed_url.port
            self.__ap_scheme = parsed_url.scheme
            self.__ap_verifyssl = verifyssl
            self.__http_session = requests.Session()
            self.__sse_client = None
        except Exception as e:
            raise ValueError("Unable to parse AirPal URL: {0}.".format(e))
        logger.debug("DEBUG: Airpal Scheme: %s, Airpal Server: %s, Airpal Port: %s",
                     self.__ap_scheme, self.__ap_server, self.__ap_port)
        return

    def login(self, username="", password=""):
        """
        Login to Airpal
        :param username: Username
        :param password: Password
        :return: Requests.Response, likely a 302.
        """
        logger.debug('login:')
        return self.rest_call("{0}://{1}:{2}/login".format(self.__ap_scheme, self.__ap_server, self.__ap_port),
                              "post",
                              {
                                  "username": username,
                                  "password": password
                              },
                              sensitive=True)

    def logout(self):
        """
        End the user session
        :return: Requests.Response, likely a 302
        """
        logger.debug('logout:')
        return self.rest_call("{0}://{1}:{2}/logout".format(self.__ap_scheme, self.__ap_server, self.__ap_port),
                              "get")

    def subscribe(self):
        """
        Subscribe to the Server Sent Event Stream
        :return: sseclient.SSEClient Object
        """
        logger.debug('subscribe:')
        self.__sse_client = sseclient.SSEClient("{0}://{1}:{2}/api/updates/subscribe".format(self.__ap_scheme,
                                                                                             self.__ap_server,
                                                                                             self.__ap_port),
                                                session=self.__http_session, chunk_size=1,
                                                verify=self.__ap_verifyssl)
        return self.__sse_client

    def next_event(self):
        """
        Grab the next event from the event_stream
        :return: sseclient.Event object
        """
        logger.debug('next_event:')
        return next(self.__sse_client)

    def wait_for_job(self, uuid, print_status=False, end_status=None, sse_error_halt=False, sse_error_max=20):
        """
        Iterate through subscribed event_stream for UUID until job is completed
        :param uuid: UUID to wait for
        :param print_status: Boolean, if True print status as looping.
        :param end_status: List of end statuses to look for.
        :param sse_error_halt: Bool on if SSE errors should cause an exception
        :param sse_error_max: Maximum number of SSE errors to allow.
        :return: dict containing value from 'job' key of final event.
        """
        logger.debug('wait_for_job:')
        cur_uuid_state = ""
        sse_error_count = 0
        job = {}

        if not end_status or not isinstance(end_status, list):
            end_statuses = ["FAILED", "FINISHED"]
            logger.debug("No end_status specified, setting end_statuses to %s.", end_statuses)
        else:
            end_statuses = end_status
            logger.debug("Set end_statuses to %s.", end_statuses)

        while cur_uuid_state not in end_statuses:
            # get the next event
            try:
                cur_event = json.loads(self.next_event().data)
            except ValueError as e:
                # malformed SSE message.
                logger.info('Malformed SSE message. (%s)', e)
                if sse_error_halt:
                    # throw exception
                    raise SSEInvalidMessageExceeded
                else:
                    # increment error counter.
                    sse_error_count += 1

                    # check if we are over max threshold.
                    if sse_error_count >= sse_error_max:
                        logger.debug('Hit max SSE error level: count %d, max %d', sse_error_count, sse_error_max)
                        raise SSEInvalidMessageExceeded
                    else:
                        # continue
                        if print_status:
                            print('INVALID_SSE_RECEIVED..')
                            logger.debug('Continuing through invalid SSE.')
                            continue
                        else:
                            logger.debug('INVALID_SSE_RECEIVED, Continuing..')
                            continue
            
            # see if job is in message
            job = cur_event.get('job')
            if not job:
                # not correct message
                logger.debug('No JOB in message: %s', cur_event)
                continue
            # get UUID
            event_uuid = job.get('uuid')
            if not event_uuid or event_uuid != uuid:
                # no UUID or UUID for a different job.
                logger.debug('UUID missing or mismatch event_uuid:%s, uuid:%s', event_uuid, uuid)
                continue
            cur_uuid_state = job.get('state')
            if print_status:
                # print status set
                print('{0}..'.format(cur_uuid_state))
            else:
                # no print, but log for debugging.
                logger.debug('%s..', cur_uuid_state)

        # loop finished, return current job info.
        return job

    def yield_csv(self, location, fd=False, raw_response=False):
        """
        Function to yield a .csv file from a location string (PATH of URL)
        :param location: String to PATH of CSV object on AirPal
        :param fd: Boolean, if True, return a File Descriptor-like object instead of content.
        :param raw_response: Boolean, if True, return raw response instead of content.
        :return: String or raw response if raw_response=True or FD-like object if fd=True
        """
        logger.debug('yield_csv:')
        status, response = self.rest_call("{0}://{1}:{2}{3}".format(self.__ap_scheme,
                                                                    self.__ap_server,
                                                                    self.__ap_port,
                                                                    location),
                                          "get",
                                          extraheaders={'Accept': "*/*"})
        if raw_response:
            return response
        elif fd:
            return io.StringIO(response.content.decode('utf8'))
        else:
            return response.content

    def execute(self, query):
        """
        Submit a query for execution
        :param query: String containing PrestoDB-SQL query for Airpal to process
        :return: Requests.Response object
        """
        logger.debug('execute:')
        return self.rest_call("{0}://{1}:{2}/api/execute".format(self.__ap_scheme, self.__ap_server, self.__ap_port),
                              "put",
                              {
                                  "query": query,
                                  "tmpTable": None
                              }, jsondata=True)

    def rest_call(self, url, method, data=None, jsondata=False, sensitive=False, extraheaders=None, timeout=60,
                  retry=None, max_retry=30, retry_sleep=10):
        """
        Generic REST call worker function
        :param url: URL for the REST call
        :param method: METHOD for the REST call
        :param data: Optional DATA for the call (for POST/PUT/etc.)
        :param jsondata: If data should be sent as JSON and not www-form-urlencoded
        :param sensitive: Flag if content request/response should be hidden from logging functions
        :param extraheaders: Extra/modified headers
        :param timeout: Requests Timeout
        :param retry: Boolean if request should be retried if failure.
        :param max_retry: Maximum number of retries before giving up
        :param retry_sleep: Time inbetween retries.
        :return: Tuple (Boolean success or failure, Requests.Response object)
        """
        logger.debug('rest_call:')

        # check for SSL verification on this session
        verify = self.__ap_verifyssl

        # Retry loop counter
        retry_count = 0
        if not extraheaders:
            extraheaders = {}

        # Run once logic.
        if not retry:
            run_once = True
        else:
            run_once = False

        if jsondata:
            # need to make sure data is cast to JSON.
            data = json.dumps(data)
            extraheaders['Content-Type'] = 'application/json'

        while retry or run_once:
            headers = {'Accept': 'application/json'}
            # if the request needs extra headers, add them.

            if extraheaders and type(extraheaders) is dict:
                for key, value in extraheaders.items():
                    headers[key] = value

            cookie = self.__http_session.cookies.get_dict()

            # disable warnings and verification if requested.
            if not verify:
                # disable warnings for SSL certs.
                urllib3.disable_warnings()

            logger.debug('url = {0}'.format(url))

            # make request
            try:
                if data:
                    # pre request, dump simple JSON debug
                    if not sensitive and (logger_level <= logging.DEBUG and logger_level != logging.NOTSET):
                        logger.debug('\n\tREQUEST: %s %s\n\tHEADERS: %s\n\tCOOKIES: %s\n\tDATA: %s\n',
                                     method.upper(), url, headers, cookie, data)

                    response = getattr(self.__http_session, method)(url, data=data, headers=headers, verify=verify,
                                                                    stream=True, timeout=timeout, allow_redirects=False)

                else:
                    # pre request, dump simple JSON debug
                    if not sensitive and (logger_level <= logging.DEBUG and logger_level != logging.NOTSET):
                        logger.debug('\n\tREQUEST: %s %s\n\tHEADERS: %s\n\tCOOKIES: %s\n',
                                     method.upper(), url, headers, cookie)

                    response = getattr(self.__http_session, method)(url, headers=headers, verify=verify, stream=True,
                                                                    timeout=timeout, allow_redirects=False)

                # if it's a non-good response, don't accept it - wait and retry
                if response.status_code not in [requests.codes.ok,
                                                requests.codes.no_content,
                                                requests.codes.found,
                                                requests.codes.moved]:

                    # Simple JSON debug
                    if not sensitive and (logger_level <= logging.DEBUG and logger_level != logging.NOTSET):
                        try:
                            logger.debug('RESPONSE HEADERS: %s\n', json.dumps(
                                json.loads(str(response.headers)), indent=4))
                        except ValueError:
                            logger.debug('RESPONSE HEADERS: %s\n', str(response.headers))
                        try:
                            logger.debug('RESPONSE: %s\n', json.dumps(response.json(), indent=4))
                        except ValueError:
                            logger.debug('RESPONSE: %s\n', str(response.text))

                    logger.debug("Error, non-200 response received: %s", response.status_code)

                    if retry:
                        # keep retrying
                        retry_count += 1
                        if retry_count >= max_retry:
                            logger.info("Max retries of %s reached.", max_retry)
                            retry = False
                        # wait a bit to see if issue clears.
                        sleep(retry_sleep)
                    else:
                        # run once is over.
                        run_once = False
                        return False, response

                else:

                    # Simple JSON debug
                    if not sensitive and (logger_level <= logging.DEBUG and logger_level != logging.NOTSET):
                        try:
                            logger.debug('RESPONSE HEADERS: %s\n', json.dumps(
                                json.loads(str(response.headers)), indent=4))
                            logger.debug('RESPONSE: %s\n', json.dumps(response.json(), indent=4))
                        except ValueError:
                            logger.debug('RESPONSE HEADERS: %s\n', str(response.headers))
                            logger.debug('RESPONSE: %s\n', str(response.text))

                    # if retries have been done, update log if requested.
                    if retry_count > 0:
                        logger.debug("Got good response after %s retries. ", retry_count)

                    # run once is over, if set.
                    run_once = False
                    return True, response

            except requests.exceptions.Timeout:

                logger.info("Error, request timeout reached.")

                if retry:
                    # keep retrying
                    retry_count += 1
                    if retry_count >= max_retry:
                        logger.info("Max retries of %s reached.", max_retry)
                        retry = False
                    # wait a bit to see if issue clears.
                    sleep(retry_sleep)
                else:
                    # run once is over.
                    # run_once = False
                    return False, None

    @staticmethod
    def noop():
        """
        NOOP function (nothing here!)
        :return: Always true
        """
        logger.debug('noop:')
        return True


class SSEInvalidMessageExceeded(Exception):
    """
    Exception thrown when an invalid message is recieved from SSEClient.
    """
    pass
