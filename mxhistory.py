import requests
from json2html import *

def mxhistory(domain, apikey):

    url = "https://api.securitytrails.com/v1/history/"+domain+"/dns/mx"

    querystring = {"apikey":apikey}

    response = requests.request("GET", url, params=querystring)

    print(response.text)


# mxhistory("test.com", "secretkey")


responsetext = """{
  "type": "mx",
  "records": [
    {
      "values": [
        {
          "priority": 30,
          "mx_count": 1282151,
          "host": "aspmx5.googlemail.com"
        },
        {
          "priority": 30,
          "mx_count": 1299754,
          "host": "aspmx4.googlemail.com"
        },
        {
          "priority": 30,
          "mx_count": 5595216,
          "host": "aspmx3.googlemail.com"
        },
        {
          "priority": 30,
          "mx_count": 5730083,
          "host": "aspmx2.googlemail.com"
        },
        {
          "priority": 10,
          "mx_count": 10117240,
          "host": "aspmx.l.google.com"
        },
        {
          "priority": 20,
          "mx_count": 9769682,
          "host": "alt2.aspmx.l.google.com"
        },
        {
          "priority": 20,
          "mx_count": 9851526,
          "host": "alt1.aspmx.l.google.com"
        }
      ],
      "type": "mx",
      "organizations": [
        "Google Inc."
      ],
      "last_seen": null,
      "first_seen": "2015-05-19"
    },
    {
      "values": [
        {
          "priority": 30,
          "mx_count": 1299754,
          "host": "aspmx4.googlemail.com"
        },
        {
          "priority": 30,
          "mx_count": 5595216,
          "host": "aspmx3.googlemail.com"
        }
      ],
      "type": "mx",
      "organizations": [
        "Google Inc."
      ],
      "last_seen": "2015-05-18",
      "first_seen": "2015-05-18"
    },
    {
      "values": [
        {
          "priority": 30,
          "mx_count": 5595216,
          "host": "aspmx3.googlemail.com"
        },
        {
          "priority": 30,
          "mx_count": 5730083,
          "host": "aspmx2.googlemail.com"
        }
      ],
      "type": "mx",
      "organizations": [
        "Google Inc."
      ],
      "last_seen": "2015-05-17",
      "first_seen": "2015-05-17"
    }
  ],
  "pages": 5,
  "endpoint": "/v1/history/test.com/dns/mx"
}"""

print(responsetext)

print(json2html.convert(json = responsetext))