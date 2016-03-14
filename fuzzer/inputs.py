import requests

class FormInput:
    def __init__(self, url, form, session):
        self.name = "FormInput"
        self.url = url
        self.form = form
        self.session = session

    def submit(self, form_input):
        payload = dict()
        for tag in self.form.descendants:
            if tag.name == 'input':
                if tag['type'] != 'submit':
                    payload[tag['name']] = form_input
                else:
                    payload[tag['type']] = tag['value']
        if self.form['method'].lower() == 'get':
            return self.session.get(self.url, data=payload, allow_redirects=True)
        elif self.form['method'].lower() == 'post':
            return self.session.post(self.url, data=payload, allow_redirects=True)

    def __str__(self):
        copy_of_form = self.form.__copy__()
        copy_of_form.clear()
        return self.name + ":\n\t" + str(self.url) + "\n\t" + str(copy_of_form) + "\n"


class CookieInput:
    """
    Class representing a Cookie Input object
    """
    def __init__(self, url, cookie_key, session):
        """
        :param url: The URL associated with each cookie input
        :param cookie_key: The unique cookie key associated with each cookie input. E.g. "Security"
        :param session: The requests session
        :return: A cookie Object
        """
        self.url = url
        self.cookie_key = cookie_key
        self.session = session

    def submit(self, vector):
        """
        :param vector: Updating the cookie with the vector value
        :return: A requests get response
        """
        cookies = self.session.cookies.copy()
        cookies.set(self.cookie_key, vector)
        response = requests.get(self.url, cookies=cookies)
        return response

    def __str__(self):
        return "CookieInput with key = " + self.cookie_key + " on " + self.url


class URLParameterInput:
    def __init__(self, session, url, parameter_key):
        self.session = session
        self.url = url
        self.parameter_key = parameter_key

    def submit(self, vector):
        full_url = self.url + '?' + self.parameter_key + '=' + vector
        return self.session.get(full_url)

    def __str__(self):
        return 'URLParameterInput at ' + self.url + '?' + self.parameter_key
