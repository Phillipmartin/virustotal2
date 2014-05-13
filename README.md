# virustotal2

A portable, Pythonic and complete implementation of the [Virustotal](https://www.virustotal.com/) [Public API](https://www.virustotal.com/en/documentation/public-api/).  It would also implement the Private API if VT would like to give me access... :)

This module is heavily inspired by, and borrows some code from, the [virustotal](https://github.com/Gawen/virustotal) module.  In particular, it uses the same rate limiting logic and deals with report updating in the same way.  I ended up re-writing the module from scratch, however, and in the process made some new choices that broke backwards compatibility.  Thus, we have virustotal2.

## Prerequisites

## Example

    import virustotal2
    import urllib2
    import csv

    vt = virustotal2.VirusTotal2(API_KEY)

    mdl_content = urllib2.urlopen("http://www.malwaredomainlist.com/updatescsv.php")
    mdl_csv = csv.reader(mdl_content)

    for line in mdl_csv:
        ip=line[2].split("/")[0]
        try:
            ip_report = vt.retrieve(ip)   #get the VT IP report for this IP
        except VirusTotal2.ApiError as e:
            print "API error: " + e + " on ip " + ip

        total_pos = sum([u["positives"] for u in ip_report.detected_urls])
        total_scan = sum([u["total"] for u in ip_report.detected_urls])
        count = len(ip_report.detected_urls)

        print "URLs hosted on "+ip+" are called malicious by " + int(total_pos/count) + " / " + int(total_scan/count) + " scanners"




## How To Use
### Install
    pip install virustotal2

### Import
    import virustotal2

### Instantiate
    vt2=virustotal2.VirusTotal2(API_KEY)

Optionally, you can pass limit_per_min, which is the number of queries you can perform per minute.  4 is the default.

### Retrieve a report
Use the method retrieve() to get an existing report from VirusTotal.  This method's first argument can be:

- an MD5, SHA1 or SHA256 of a file or a list of hashes
- a path to a file or a list of paths to files
- a URL or a list of URLs
- an IP address
- a domain name

retrieve() will attempt to auto-detect what you're giving it.  If you want to be explicit, you can use the type parameter with the values:

- ip
- domain
- hash
- file
- url

Finally, if you want raw JSON back, as opposed to a VirusTotal2Report object, you can pass in raw=1.

If you pass retrieve() a list of items, you will get a list of reports back in the same order.  In order to preserve that semantic, if you pass in a list of files, some of which are invalid, you will get a list of reports and None back.


### Scan a new file
Use the scan() method to scan a new URL or file.  This method's first argument can be:

- a path to a file or list of paths to files
- a url or list of URLs

scan() will attempt to auto-detect what you're giving it.  If you want to be explicit, you can use the type parameter with the values:

- file
- url

If you want raw JSON back, as opposed to a VirusTotal2Report object, you can pass in raw = 1.

Finally, if you want force a reanalysis of the resource you are passing in, set reanalyze = 1.  Note that the VirusTotal API currently does not allow URLs to be reanalyzed.

If you pass scan() a list of items, you will get a list of reports back in the same order.  In order to preserve that semantic, if you pass in a list of files, some of which are invalid, you will get a list of reports and None back.

### Using a Report
The retrieve() and scan() methods return VirusTotal2Report objects.  These objects have some useful methods and also act as pass-thrus to the underlying JSON.

#### wait(callback=None, preempt=0, interval=60)
This method blocks until the file you've submitted for scanning is finished scanning.  THIS CAN TAKE A VERY LONG TIME.  If invoked with a callback, using the callback parameter, the waiting will be done in the background and your callback will be called when the report is ready.

If you call wait() while an asynchronus wait is already pending there are a few possible outcomes.  If you call it with the same callback, nothing happens.  If you call it with a new callback, that callback gets added to the callback stack.  If you call it without a callback, implying a blocking call,THE WORLD EXPLODES.

#### iswaiting()
returns true if this report is waiting already

#### status()
returns "analyzing", "ok" or "error" based on the underlying value returned by virustotal.

#### rescan()
requests virustotal to rescan the sample that created the current report.  This is only valid for file or url reports.  This method modifies the current report rather than returning a new report object, so the following is normal:

    >>> import virustotal2
    >>> vt = virustotal2.VirusTotal2(API_KEY)
    >>> report = vt.get("www.evilsite.com/evil.exe")
    >>> report.status()
    analyzing
    >>> report.wait()
    >>> report.status()
    ok
    >>> report.rescan()
    >>> report.status()
    analyzing
    >>> report.wait()
    >>> report.status()
    ok

#### update()
checks to see if virustotal has completed it's analysis yet.

## References
[Virustotal Public API](https://www.virustotal.com/en/documentation/public-api/)

