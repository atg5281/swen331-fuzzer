class FormInput:
    def __init__(self, url, tag, session):
        self.name = "FormInput"
        self.url = url
        self.tag = tag
        self.session = session

    def submit(self, form_input):
        return self.session.post(self.url, data=form_input, allow_redirects=True)

    def __str__(self):
        return self.name + ":\n\t" + str(self.url) + "\n\t" + str(self.tag) + "\n"


class CookieInput:
    def __init__(self, url, cookie_key):
        pass

    def submit(self, vector):
        pass

    def __str__(self):
        return "CookieInput"


class URLParameterInput:
    def __init__(self, session, url, parameter_key):
        print('Creating a URLParameterInput with url = ' + url + ' and parameter_key = ' + parameter_key)
        self.session = session
        self.url = url
        self.parameter_key = parameter_key

    def submit(self, vector):
        full_url = self.url + '?' + self.parameter_key + '=' + vector
        return self.session.get(full_url)

    def __str__(self):
        return 'URLParameterInput at ' + self.url + '?' + self.parameter_key
