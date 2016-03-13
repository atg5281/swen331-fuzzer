import requests


class FormInput:
    def __init__(self, url, tag):
        self.name = "FormInput"
        self.url = url
        self.tag = tag

    def submit(self, input):
        return requests.post(self.url, data=input, allow_redirects=True)

    def __str__(self):
        return "FormInput"


class CookieInput:
    def __init__(self, url, cookie_key):
        pass

    def submit(self):
        pass

    def __str__(self):
        return "CookieInput"


class URLParameterInput:
    def __init__(self, url, parameter_key):
        pass

    def submit(self):
        pass

    def __str__(self):
        return "URLParameterInput"
