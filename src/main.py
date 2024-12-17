import tweepy, tweepy.client 

import seaborn # Used to post tweet

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


# assuming vulnarabilites is not 0!
def filterOutputCVE(cveObj: dict) -> str:

    data = ["id", "sourceIdentifier", "published", "vulnStatus"]

    format = []

    for element in data:
        missing_message = f"{element} not present!"
        format.append(f"{element}: {cveObj.get(element,missing_message )}")

    metrics = next(iter(cveObj["metrics"]), None)

    if metrics is not None:
        if len(metrics) >= 2:
            dataMetrics = cveObj["metrics"][metrics][0]["cvssData"]
            format.append("BaseSeverity: " + dataMetrics.get("baseSeverity", "N/A"))
            format.append("baseScore: " + str(dataMetrics.get("baseScore", "N/A")))
            
    if cveObj["references"] is not None:
        format.append(cveObj["references"][0].get("url","N/A"))

    # if cveObj.get("descriptions") is None:
    #     format.append("Description: No description present!")
    # else:
    #     msg = cveObj["descriptions"][0].get("value", "no description is present")
    #     format.append(f"Description: {msg}")

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
    str = f"\n{key}:\n"

    val = dict.get(key)

    for e in val:
        for inner in e:
            str = str + inner + "\n"

    return str


def tweet():

    api = tweepy.Client(
        bearer_token=E.getenv("BEARER_TOKEN"),
        consumer_key=E.getenv("API_KEY"),
        consumer_secret=E.getenv("API_SECRET_KEY"),
        access_token=E.getenv("ACCESS_TOKEN"),
        access_token_secret=E.getenv("ACCESS_SECRET_TOKEN"),
    )

    data = getResults()

    os = ["Windows", "MacOs", "Linux"]

    str = f"Date:{date.today()}\n"

    print(toStr(data, "MacOs"))
    
    # api.create_tweet(text =toStr(data, "Linux") )


tweet()


# refractor code so when we output theres one cve per index, basically combine it into one object. Add code to not post if theres no new vulnerabilities 
