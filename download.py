import time
import requests
from datetime import datetime, timedelta
import arrow


"""https://nvd.nist.gov/developers/vulnerabilities"""


def historical_cve(start_date, end_date):
    
    s = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",

    }
    s.headers.update(headers)
    
    url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
    """eventName optional
        Initial Analysis: The NVD performs its initial analysis to enrich the CVE record with reference tags, CVSS base metrics, CWE, and CPE applicability statements.

        Reanalysis: The NVD performs further analysis resulting in some modification to the CVE record.

        CVE Modified: An approved source modifies a CVE record published in the NVD. The modification's source is identified on the details page in the event name and in the API response by the value of the sourceIdentifer.

        Modified Analysis: After an approved source modified a previously analyzed CVE record, the NVD performs further analysis.

        CVE Translated: An approved translator provides a non-English translation for the CVE record.

        Vendor Comment: The NVD updates the CVE record with additional information from the product vendor.

        CVE Source Update: The NVD updates the information on a source that contributed to the CVE record.

        CPE Deprecation Remap: The NVD updates the match criteria associated with the CVE record based on changes to the CPE dictionary. This event occurs separate from analysis.

        CWE Remap: The NVD updates the weakness associated with the CVE record. This event occurs separate from analysis.

        CVE Rejected: An approved source rejects a CVE record. Rejections occurs for one or more reasons, including duplicate CVE entries, withdraw by the original requester, incorrect assignment, or some other administrative reason.

        CVE Unrejected: An approved source re-published a CVE record previously marked rejected.
    """
    PAGE_SIZE = 5000
    offset = 0
    params = dict(
        # eventName="Initial Analysis",
        changeStartDate=start_date.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
        changeEndDate=end_date.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
        resultsPerPage=PAGE_SIZE,
        startIndex=offset
    )
    data = []
    while True:
        print(params)
        try:
            r = s.get(url, params=params)
            resp = r.json()
        except Exception as e:
            e
        for d in resp['cveChanges']:
            data.append(d['change'])

        if len(data) == resp['totalResults']:
            break
        params["startIndex"] += PAGE_SIZE
        time.sleep(15)
    
    return data


if __name__ == '__main__':
    PERIOD = 100
    start_date = arrow.get("2015-01-01T00:00:00Z")
    end_date = arrow.get("2021-01-01T00:00:00Z")
    cves = []
    while start_date < end_date:
        mid_end = start_date + timedelta(days=PERIOD)
        if end_date < mid_end:
            mid_end = end_date
        cves.extend(historical_cve(start_date, mid_end))
        start_date = mid_end

    cves