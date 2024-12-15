import tweepy  # Used to post tweet

import requests  # Used to call the NDV api

from datetime import datetime

import tweepy.client


apiKey = "xYp6UXjI6rSpp9clBzGVbhWW8"

privApiKey = "#cM9YPejKWB7cgId3T3Em4aA7nnPNWAmeQuDFCUSzkz0Ub3Hbrj"

accToken = "1868131492800663552-r1kTDkvAGmV8hrzzp3qQvNg8CRK5Y6"

privAccToken = "VpD10P8LQOFDEzNV0LstvXY6kr5Ak3jn9hgQIpWqxcO0f"

bearer_token="AAAAAAAAAAAAAAAAAAAAABs3xgEAAAAAu6PGtsHB3IzVWgQiLHH3SlmKJI4%3DEj0KIQogFzL0fy1B9HZhm8RveIC9YJdovvU5oOSUqGtTCsBS7h"

from datetime import datetime, timedelta, timezone


# generate UTC start and end times
def getDate(day=3):
    return [
        (datetime.now(timezone.utc) - timedelta(days=day)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ]


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
            headers={"apiKey": "d15538a9-480e-44de-8290-8cffd6292863"},
        )
        request.raise_for_status()
        return request.json()

    except requests.exceptions.RequestException as error:
        print(f"An error occurred:{error}")


# assuming vulnarabilites is not 0!
def filterOutputCVE(cveObj: dict) -> str:

    data = ["id", "sourceIdentifier", "published", "vulnStatus"]

    format = []

    for element in data:
        missing_message = f"{element} not present!"
        format.append(f"{element}: {cveObj.get(element,missing_message )}")

    if cveObj.get("descriptions") is None:
        format.append("Description: No description present!")
    else:
        msg = cveObj["descriptions"][0].get("value", "no description is present")
        format.append(f"Description: {msg}")

    return format


def callAPI(format):

    data = getData(format)
    filterOutput = []
    if len(data["vulnerabilities"]) == 0:
        filterOutput.append([f"{format} has no known vulnerabilities"])
        return filterOutput

    for element in data["vulnerabilities"]:

        filterOutput.append(filterOutputCVE(element.get("cve")))

    return filterOutput


def getResults():

    os = ["Windows", "MacOs", "Linux"]
    filteredData = {}
    for e in os:
        filteredData[e] = callAPI(e)
        
    return filteredData


def toStr(dict: dict, key):
    str = f"{key}:" + "\n" + "\n"

    val = dict.get(key)

    for e in val:
        for inner in e:
            str = str + inner + "\n"

    return str


def tweet():


    obj = getResults()
    keys = ["Windows", "MacOs", "Linux"]
    
    


