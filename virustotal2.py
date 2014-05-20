#!/usr/bin/env python

import threading
from itertools import izip_longest
import os
import urlparse
import re
import json
import time
import urllib2
import urllib
import hashlib
import requests


class VirusTotal2(object):
    _SCAN_ID_RE = re.compile(r"^[a-fA-F0-9]{64}-[0-9]{10}$")

    def __init__(self, api_key, limit_per_min=None):
        limit_per_min = limit_per_min if limit_per_min is not None else 4

        super(VirusTotal2, self).__init__()

        self.api_key = api_key
        self.limit_per_min = limit_per_min
        self.limits = []
        self.limit_lock = threading.Lock()

    #we only scan files and URLs
    def scan(self, thing, thing_type=None, raw=False, rescan=False):
        """
        Submit a file to or URL to VirusTotal for scanning.
        Returns a VirusTotal2Report object

        Keyword arguments:
         thing - a file name on the local system or a URL or list of URLs
         thing_type - Optional, a hint to the function as to what you are sending it
         raw - Optional, if True return the raw JSON output from VT

        Raises a TypeError if it gets something other than a file or URL/list of URLs
        Raises an TypeError if VirusTotal returns something we can't parse.
        """
        #identify the thing
        thing_id = self._whatisthing(thing)
        if thing_type is None:
            thing_type = thing_id

        data = {"apikey": self.api_key}

        #set up and execute the query based on what the thing is
        #we can only take URLs and Files for scan()
        if thing_type == "url":
            endpoint = "https://www.virustotal.com/vtapi/v2/url/scan"
            if isinstance(thing, list):
                data["url"] = "\n".join(thing)
            else:
                data["url"] = thing

            req = urllib2.Request(endpoint, urllib.urlencode(data))
            self._limit_call_handler()
            result = urllib2.urlopen(req).read()

        elif thing_type == "file" and rescan is False:
            endpoint = "https://www.virustotal.com/vtapi/v2/file/scan"
            with open(thing, 'rb') as f:
                file_contents = f.read()

            self._limit_call_handler()
            result = requests.post(endpoint, data=data, files={"file": (os.path.basename(thing), file_contents)}).text
        elif thing_type == "file" and rescan is True:
            endpoint = "https://www.virustotal.com/vtapi/v2/file/rescan"
            fh = open(thing, 'rb')
            content = fh.read()
            data["resource"] = hashlib.sha256(content).hexdigest()

            req = urllib2.Request(endpoint, urllib.urlencode(data))
            self._limit_call_handler()
            result = urllib2.urlopen(req).read()
        elif thing_type == "hash" and rescan is True:
            endpoint = "https://www.virustotal.com/vtapi/v2/file/rescan"
            if isinstance(thing, list):
                data["resource"] = ", ".join(thing)
            else:
                data["resource"] = thing

            req = urllib2.Request(endpoint, urllib.urlencode(data))
            self._limit_call_handler()
            result = urllib2.urlopen(req).read()
        elif thing_type == "hash" and rescan is not True:
            raise TypeError("Hahses can only be re-scanned, please set rescan=True")
        else:
            raise TypeError("Unable to scan type '"+thing_type+".")

        #should we just return raw JSON?
        if raw:
            return result

        return self._generate_report(result, thing_id, thing)

    def retrieve(self, thing, thing_type=None, raw=False):
        """
        Retrieve a report from VirusTotal based on a hash, IP, domain, file or URL.  NOTE: URLs must include the scheme
         (e.g. http://)
        Returns a VirusTotal2Report object

        Keyword arguments:
         thing - a file name on the local system, a URL or list of URLs,
            an IP or list of IPs, a domain or list of domains, a hash or list of hashes
         thing_type - Optional, a hint to the function as to what you are sending it
         raw - Optional, if True return the raw JSON output from VT

        Raises a TypeError if it gets something other than a filename, URL, IP domain or hash
        Raises an TypeError if VirusTotal returns something we can't parse.
        """
        #trust the user-supplied type over the automatic identification
        thing_id = self._whatisthing(thing)
        if thing_type is None:
            thing_type = thing_id

        data = {"apikey": self.api_key}

        if thing_type == "url":
            endpoint = "http://www.virustotal.com/vtapi/v2/url/report"
            if isinstance(thing, list):
                data["resource"] = "\n".join(thing)
            else:
                data["resource"] = thing

            req = urllib2.Request(endpoint, urllib.urlencode(data))

        elif thing_type == "ip":
            endpoint = "http://www.virustotal.com/vtapi/v2/ip-address/report"
            #IPs don't support bulk queries
            if isinstance(thing, list):
                raise TypeError
            data["ip"] = thing

            req = urllib2.Request("%s?%s" % (endpoint, urllib.urlencode([(k, v) for k, v in data.items()])))

        elif thing_type == "file":
            endpoint = "http://www.virustotal.com/vtapi/v2/file/report"
            hashes = []
            if not isinstance(thing, list):
                thing = [thing]

            for f in thing:
                fh = open(f, 'rb')
                content = fh.read()
                hashval = hashlib.sha256(content).hexdigest()
                hashes.append(hashval)

            data["resource"] = ", ".join(hashes)

            req = urllib2.Request(endpoint, urllib.urlencode(data))

        elif thing_type == 'domain':
            endpoint = "http://www.virustotal.com/vtapi/v2/domain/report"
            #domains don't support bulk queries
            if isinstance(thing, list):
                raise TypeError
            data["domain"] = thing

            req = urllib2.Request("%s?%s" % (endpoint, urllib.urlencode([(k, v) for k, v in data.items()])))

        elif thing_type == 'hash':
            endpoint = "http://www.virustotal.com/vtapi/v2/file/report"
            if isinstance(thing, list):
                data["resource"] = ", ".join(thing)
            else:
                data["resource"] = thing

            req = urllib2.Request(endpoint, urllib.urlencode(data))

        elif thing_type == "scanid":
            #TODO ???
            raise TypeError

        else:
            raise TypeError("Unable to scan type '"+thing_type+".")

        #blocks until we won't violate the 4 queries per min rule
        self._limit_call_handler()

        #result here is a json string
        result = urllib2.urlopen(req).read()

        #should we just return raw JSON?
        if raw:
            return result

        return self._generate_report(result, thing_id, thing)

    def _generate_report(self, result, thing_id, thing):
        """
        Generate a VirusTotal2Report object based on the passed JSON
        Returns a VirusTotal2Report object

        Keyword arguments:
         result - a JSON string to parse into a report.
         thing - the item we're reporting on
         thing_id - what kind of item thing is

        Raises an TypeError if report is something we can't parse.
        """
        report = []

        if isinstance(result, basestring):
            try:
                obj = json.loads(result)
                if isinstance(obj, dict):
                    #one result
                    report.append(VirusTotal2Report(obj, self, thing_id, thing))
                else:
                    #obj is a list
                    for (i, rep) in enumerate(obj):
                        report.append(VirusTotal2Report(rep, self, thing_id, thing[i]))
            except:
                raise TypeError("VT String unparsable: "+str(result))
        else:
            raise TypeError("VT String unparsable: "+result)

        return report if len(report) > 1 else report[0]

    def _limit_call_handler(self):
        """
        Ensure we don't exceed the 4 requests a minute limit by leveraging a thread lock

        Keyword arguments:
            None
        """
        with self.limit_lock:
            if self.limit_per_min <= 0:
                return

            now = time.time()
            self.limits = [l for l in self.limits if l > now]
            self.limits.append(now + 60)

            if len(self.limits) >= self.limit_per_min:
                time.sleep(self.limits[0] - now)

    @staticmethod
    def _grouped(iterable, n):
        """
        take a list of items and return a list of groups of size n.  Fill any missing values at the end with None

        Keyword arguments:
            n - the size of the groups to return
        """
        return izip_longest(*[iter(iterable)] * n, fillvalue=None)

    # noinspection PyTypeChecker
    def _whatisthing(self, thing):
        """
        Bucket the thing it gets passed into the list of items VT supports
        Returns a sting or "unknown"

        Keyword arguments:
            thing - a string to identify
        """
        if isinstance(thing, list):
            thing = thing[0]
        #per the API, bulk requests must be of the same type
        #ignore that you can intersperse scan IDs and hashes for now
        #...although, does that actually matter given the API semantics?

        elif isinstance(thing,str) and os.path.isfile(thing):
            #thing==filename
            return "file"

        #implied failure case, thing is neither a list or a file, so we assume string
        if not isinstance(thing, basestring):
            return "unknown"

        #Is a hash
        if all(i in "1234567890abcdef" for i in str(thing).lower()) and len(thing) in [32, 40, 64]:
            return "hash"

        # Is IP address
        if all(i in "1234567890." for i in thing) and len(thing) <= 15:
            return "ip"

        # Is domain name
        if "." in thing and "/" not in thing:
            return "domain"

        #Is scan ID
        if self._SCAN_ID_RE.match(thing):
            return "scanid"

        # Is URL ?
        if urlparse.urlparse(thing).scheme:
            return "url"

        return "unknown"


class VirusTotal2Report(object):
    def __init__(self, obj, parent, thing_id, query):

        super(VirusTotal2Report, self).__init__()

        self.scan = parent
        self._json = obj
        self.type = thing_id
        self.query = query

        #initial API calls return response_code = 1
        #we expect -2, as the scan is queued, so we update to get what we think we should have,
        self.update()

    def __repr__(self):
        return "<VirusTotal2 report %s (%s)>" % (
            self.id,
            self.status,
        )

    def __iter__(self):
        if self.type == "ip":
            for resolution in self.resolutions.iteritems():
                yield resolution
        elif self.type == "domain":
            for resolution in self.resolutions.iteritems():
                yield resolution
        elif self.type == "url":
            for scanner, report in self.scans.iteritems():
                yield (scanner, report["result"])
        else:
            for antivirus, report in self.scans.iteritems():
                yield (
                    (antivirus, report["version"], report["update"]),
                    report["result"],
                )

    def __getattr__(self, attr):
        item = {
            "id": "resource",
            "status": "verbose_msg",
        }.get(attr, attr)

        try:
            return self._json[item]

        except KeyError:
            raise AttributeError(attr)

    def update(self):
        """
        Re-query the Virustotal API for new results on the current object.  If the current object is listed as
        not in VirusTotal (can be the case with IPs or domains), this function does nothing.

        Keyword arguments:
            none

        Raises:
            TypeError if we don't get JSON back from VT
        """
        if self.response_code == 0:
            #it wasn't there the first time.  why try again?
            # or we already have complete results.  why update without a rescan?
            return

        if self.type in ("ip", "domain"):
            data = self.scan.retrieve(self.query, raw=True)
        elif self.type == "file":
            data = self.scan.retrieve(self.scan_id, thing_type="hash", raw=True)
        else:
            data = self.scan.retrieve(self.scan_id, thing_type=self.type, raw=True)

        try:
            self._json = json.loads(data)
        except:
            raise TypeError

    def rescan(self):
        #only applies to files and URLs
        """
        Requests a rescan of the current file.  This API only works for reports that have been generated from files or
          hashes.

        Keyword arguments:
            none

        Raises:
            TypeError if we don't get JSON back from VT
        """
        if self.type in ("file", "hash"):
            data = self.scan.retrieve(self.scan_id, thing_type="hash", raw=True, rescan=True)
        else:
            raise TypeError("cannot rescan type "+self.type)

        try:
            self._json = json.loads(data)
        except:
            raise TypeError

    def wait(self):
        """
        Wait until the Virustotal API is done scanning the current object.  If the current object is listed as not in
        VirusTotal (can be the case with IPs or domains), or we already have results this function returns immediately.

        Keyword arguments:
            none

        Raises:
            TypeError if we don't get JSON back from VT (it would pass through from the update() function)
        """
        interval = 60

        self.update()
        while self.response_code not in (1, 0):
            time.sleep(interval)
            self.update()