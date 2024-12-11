#!/usr/bin/env python3
import requests
import config

def login():
    api_endpoind = "https://" + config.url + "/login"

    payload = {
        "username": config.api_key,
        "password": config.api_secret
    }
    headers = {
     'Content-Type': 'application/json; charset=UTF-8',
     'Accept': 'application/json; charset=UTF-8'
    }

    response = requests.request("POST", api_endpoind, headers=headers, json=payload)

    return response.text



