import tweepy
import tweepy.client

import requests

from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

import os as E

import random

import tweepy.errors


# Load the .env file
load_dotenv()


# generate UTC start and end times
def getDate(day=1):
    return [
        (datetime.now(timezone.utc) - timedelta(days=day)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    ]


# Returns json data
def callApi():
    formatted_start_date, formatted_end_date = getDate()
    try:
        request = requests.get(
            url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": formatted_start_date,
                "pubEndDate": formatted_end_date,
                "resultsPerPage": 20,
            },
            headers={"apiKey": E.getenv("DATABASE_API_KEY")},
        )
        request.raise_for_status()
        return request.json()

    except requests.exceptions.RequestException as error:
        print(f"An error occurred:{error}")


# assuming vulnerabilities is not 0! HAVE THIS RETURN AN OBJECT(DICT)
def getVulnObj(cveObj: dict) -> str:
    data = ["id", "published"]

    vulObj = {}

    for element in data:
        vulObj[element] = cveObj.get(element, "N/A")

    metrics = next(iter(cveObj["metrics"]), None)

    if metrics is not None:
        if len(metrics) >= 2:
            dataMetrics = cveObj["metrics"][metrics][0]["cvssData"]
            vulObj["BaseSeverity"] = dataMetrics.get("baseSeverity", "")

    if cveObj["references"] is not None:
        vulObj["url"] = cveObj["references"][0].get("url", "")

    if cveObj["descriptions"] is not None:
        vulObj["description"] = cveObj["descriptions"][0].get("value", "")

    return vulObj


def getData():
    data = callApi()
    arrOfVuln = []
    if len(data["vulnerabilities"]) == 0:  # no new vulnerabilities
        return arrOfVuln

    for element in data["vulnerabilities"]:
        arrOfVuln.append(getVulnObj(element.get("cve")))

    return arrOfVuln


def format_iso_to_mmddyyyy(iso_date_str):
    """
    Converts an ISO 8601 date string (e.g. 2025-01-03T09:15:05.983)
    into a more traditional MM/DD/YYYY hh:mm:ss AM/PM format (e.g. 01/03/2025 09:15:05 AM).
    """
    # If you're on Python 3.7+, fromisoformat can parse fractional seconds automatically
    dt = datetime.fromisoformat(iso_date_str)

    # %m = 2-digit month
    # %d = 2-digit day
    # %Y = 4-digit year
    # %I = 12-hour clock
    # %M = minute
    # %S = second
    # %p = AM/PM
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


# def remove_unwanted_chars(s):
#     # Characters we want to remove:
#     chars_to_remove = [
#         "{",
#         "}",
#         "'",
#     ]

#     for ch in chars_to_remove:
#         s = s.replace(ch, "")
#     return s


def changeDateFormat(arr):
    copyArr = list(arr)
    for element in copyArr:
        date = element.get("published")  # noqa: F811

        if date:
            element["published"] = format_iso_to_mmddyyyy(date)

    return copyArr


def dict_to_multiline_string(my_dict):
    lines = []

    for key, value in my_dict.items():
        if key == "description" or key == "id" or key == "published":
            lines.append(f"{value}")

        if key == "BaseSeverity":
            lines.append(f"{key}: {value}")
        
    lines.append(my_dict["url"])

    return "\n".join(lines)


def createTweet(dict, index):
    noUrlTweet = dict_to_multiline_string(dict[index])

    charLength = len(noUrlTweet)

    CHARLIMIT = 280

    if charLength <= CHARLIMIT:
        return noUrlTweet

    else:
        diff = charLength  - 280

        description = dict[index]["description"]

        dict[index]["description"] = description[: -diff - 3] + "..."

        return dict_to_multiline_string(dict[index])


def tweet():
    api = tweepy.Client(
        bearer_token=E.getenv("BEARER_TOKEN"),
        consumer_key=E.getenv("API_KEY"),
        consumer_secret=E.getenv("API_SECRET_KEY"),
        access_token=E.getenv("ACCESS_TOKEN"),
        access_token_secret=E.getenv("ACCESS_SECRET_TOKEN"),
    )

    data = changeDateFormat(getData())

    setOfTweets = set()
    setOfLinks = set()

    for _i in range(0, 5):
        randomIdx = random.randint(0, len(data) - 1)
        tweet = createTweet(data, randomIdx)

        link = data[randomIdx]["url"]

        if tweet in setOfTweets or link in setOfLinks:
            continue
        setOfTweets.add(tweet)
        setOfLinks.add(link)
        try:
            print(f"{tweet}")
            api.create_tweet(text=tweet)
            print("Success!")

        except tweepy.errors.TooManyRequests as e:
            print(e.response)
            print(e.api_messages)
            raise e

        except tweepy.errors.Forbidden:
            continue

