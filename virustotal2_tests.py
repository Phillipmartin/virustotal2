#!/usr/bin/env python

import virustotal2
import pytest
import time
import base64


def setup_module(module):
    global vt
    #we need this global so we don't exceed our API query limit during testing
    #and fixtures are instantiated every time.  :(
    vt = virustotal2.VirusTotal2("b2510b80fec019d8b6896a8e575022690efecdfa858d1077c75b37dae5f4621e")


def test_retrieve_ip():
    report = vt.retrieve("1.1.1.1")
    assert isinstance(report, object)

    report_list = vt.retrieve(["2.2.2.2", "3.3.3.3"])
    assert isinstance(report_list, list)
    assert len(report_list) == 2


def test_retrieve_hash():
    report = vt.retrieve("cf8bd9dfddff007f75adf4c2be48005cea317c62")
    report_list = vt.retrieve(["cf8bd9dfddff007f75adf4c2be48005cea317c62", "3f786850e387550fdab836ed7e6dc881de23001b"])

    assert isinstance(report, object)
    assert isinstance(report_list, list)
    assert len(report_list) == 2


def test_retrieve_file(tmpdir):
    p = tmpdir.mkdir("sub").join("eicar")
    #base64-encoded EICAR (www.eicar.org) test file
    #the base64 is a trivial effort to try to make AV products not detect this test file as a virus
    #although they will likely get angry at the file it writes out
    p.write(
      base64.b64decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK")
    )
    report = vt.retrieve(str(p))

    assert isinstance(report, object)

def test_retrieve_base64file(tmpdir):
    p = tmpdir.mkdir("sub").join("eicar.base64")
    #base64-encoded EICAR (www.eicar.org) test file
    #the base64 is a trivial effort to try to make AV products not detect this test file as a virus
    #although they will likely get angry at the file it writes out
    p.write(
      "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK"
    )
    report = vt.retrieve(str(p))

    assert isinstance(report, object)


def test_retrieve_domain():
    report = vt.retrieve("www.google.com")
    assert isinstance(report, object)


def test_retrieve_url():
    report = vt.retrieve("https://www.google.com")
    report_list = vt.retrieve(["http://www.google.com", "http://www.slashdot.org", "http://www.reddit.com"])
    long_report_list = vt.retrieve(["http://www.google.com", "http://www.slashdot.org", "http://www.reddit.com",
                                    "http://www.cnn.com", "http://www.yahoo.com"])

    assert isinstance(report_list, list)
    assert isinstance(long_report_list, list)
    assert isinstance(report, object)
    assert len(report_list) == 3
    assert len(long_report_list) == 5


def test_detect_url():
    url = "http://www.example.com"
    what = vt._whatisthing(url)
    assert what == "url"


def test_detect_file(tmpdir):
    p = tmpdir.mkdir("sub").join("hello.txt")
    p.write("content")
    what = vt._whatisthing(str(p))
    assert what == "file_name"


def test_detect_ip():
    ip = "1.1.1.1"
    what = vt._whatisthing(ip)
    assert what == "ip"


def test_detect_sha1():
    sha1 = "3f786850e387550fdab836ed7e6dc881de23001b"
    what = vt._whatisthing(sha1)
    assert what == "hash"


def test_detect_md5():
    md5 = "60b725f10c9c85c70d97880dfe8191b3"
    what = vt._whatisthing(md5)
    assert what == "hash"


def test_detect_sha256():
    sha256 = "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7"
    what = vt._whatisthing(sha256)
    assert what == "hash"


def test_detect_scanid():
    scanid = "7f0b8caeb4980b263e6a11eeb7a02df01523f70f2fc4e3e8d4d828ffb9f4a3e4-1320826561"
    what = vt._whatisthing(scanid)
    assert what == "scanid"


def test_detect_list():
    mylist = ["1.1.1.1", "2.2.2.2"]
    what = vt._whatisthing(mylist)
    assert what == "ip"


def test_grouped():
    mylist = [1, 2, 3, 4, 5, 6, 7]
    l = [n for n in vt._grouped(mylist, 4)]

    assert len(l) == 2
    assert l[0] == (1, 2, 3, 4)
    assert l[1] == (5, 6, 7, None)


def test_call_limit():
    now = int(time.time())
    vt._limit_call_handler()
    vt._limit_call_handler()
    vt._limit_call_handler()
    vt._limit_call_handler()
    now2 = int(time.time())
    assert now2 - now >= 60


def test_scan_ip():
    with pytest.raises(TypeError):
        report = vt.scan("90.156.201.27")


def test_scan_hash():
    with pytest.raises(TypeError):
        report = vt.scan("87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7")


def test_scan_domain():
    with pytest.raises(TypeError):
        report = vt.scan("www.google.com")


def test_scan_file(tmpdir):
    p = tmpdir.mkdir("sub").join("eicar")
    #base64-encoded EICAR (www.eicar.org) test file
    #the base64 is a trivial effort to try to make AV products not detect this test file as a virus
    #although they will likely get angry at the file it writes out
    p.write(
      base64.b64decode("WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCoK")
    )
    report = vt.scan(str(p))

    assert isinstance(report, object)


def test_scan_url():
    report = vt.scan("https://www.google.com")
    report_list = vt.scan(["http://www.google.com", "http://www.slashdot.org", "http://www.reddit.com"])

    assert isinstance(report_list, list)
    assert isinstance(report, object)


if __name__ == '__main__':
    print "*NOTE* Tests are rate-limited, so they may take a long time to run!"
    pytest.main()