import tweepy
import tweepy.client

# Used to post tweet

import requests  # Used to call the NDV api

from datetime import datetime, date, timedelta, timezone

from dotenv import load_dotenv

import os as E

# Load the .env file
load_dotenv()


# generate UTC start and end times
def getDate(day=7):
    return [
        (datetime.now(timezone.utc) - timedelta(days=day)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ]

#Returns json data 
def getData(keyword):
    formatted_start_date, formatted_end_date = getDate()
    try:
        request = requests.get(
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": formatted_start_date,
                "pubEndDate": formatted_end_date,
                "resultsPerPage": 20,
                "keywordSearch": keyword,
            },
            headers={"apiKey": E.getenv("DATABASE_API_KEY")},
        )
        request.raise_for_status()
        return request.json()

    except requests.exceptions.RequestException as error:
        print(f"An error occurred:{error}")


# assuming vulnarabilites is not 0! HAVE THIS RETURN AN OBJECT(DICT)
def getVulnObj(cveObj: dict) -> str:
    data = ["id", "sourceIdentifier", "published", "vulnStatus"]

    vulObj = {}

    for element in data:
        vulObj[element] = cveObj.get(element,"N/A")
       
    metrics = next(iter(cveObj["metrics"]), None)

    if metrics is not None:
        if len(metrics) >= 2:
            dataMetrics = cveObj["metrics"][metrics][0]["cvssData"]
            vulObj["BaseSeverity"] = dataMetrics.get("baseSeverity", "N/A")
            vulObj["BaseScore"] = dataMetrics.get("baseScore", "N/A")

    if cveObj["references"] is not None:
        vulObj["url"] = cveObj["references"][0].get("url", "N/A")

  
    return vulObj


def callAPI(format):
    data = getData(format)
    arrOfVuln = []
    if len(data["vulnerabilities"]) == 0: # no new vulnarabilites
        return arrOfVuln
        
    for element in data["vulnerabilities"]:
        arrOfVuln.append(getVulnObj(element.get("cve")))

    return arrOfVuln






print(callAPI("Windows"))


# refractor code so when we output theres one cve per index, basically combine it into one object. Add code to not post if theres no new vulnerabilities
