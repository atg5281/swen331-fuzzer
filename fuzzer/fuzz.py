from bs4 import BeautifulSoup
import getopt
from functools import reduce
from inputs import FormInput, CookieInput, URLParameterInput
import requests
import sys
from urllib.parse import urljoin, urlparse, parse_qsl


helpStr = ("COMMANDS:\n"
           "\tdiscover  Output a comprehensive, human-readable list of all discovered inputs to the system."
           "Techniques include both crawling and guessing.\n"
           "\ttest      Discover all inputs, then attempt a list of exploit vectors on those inputs."
           "Report potential vulnerabilities.\n"
           "OPTIONS:\n"
           "\t--custom-auth=string     Signal that the fuzzer should use hard-coded authentication for a specific "
           "application (e.g. dvwa). Optional.\n\n"
           "\tDiscover options:\n"
           "\t--common-words=file    Newline-delimited file of common words to be used in page guessing and input "
           "guessing. Required.\n\n"
           "\tTest options:\n"
           "\t--vectors=file         Newline-delimited file of common exploits to vulnerabilities. Required.\n"
           "\t--sensitive=file       Newline-delimited file data that should never be leaked. It's assumed that this "
           "data is in the application's database (e.g. test data), but is not reported in any response. Required.\n"
           "\t--random=[true|false]  When off, try each input to each page systematically.  When on, choose a random "
           "page, then a random input field and test all vectors. Default: false.\n"
           "\t--slow=500             Number of milliseconds considered when a response is considered \"slow\". "
           "Default is 500 milliseconds\n")


def main(argv):
    """Process all of the arguments for the fuzzer
    argv -- the list of arguments
    """
    if len(argv) < 1:
        print('Must specify a command.\n')
        print(helpStr)
        return

    try:
        if argv[0] != 'discover' and argv[0] != 'test':
            raise getopt.GetoptError("")
        else:
            command = argv[0]
            arguments = argv[2:] if len(argv) > 1 else []
            opts, args = getopt.getopt(arguments, "", ['custom-auth=', 'common-words=', 'vectors=', 'sensitive=',
                                                       'random=', 'slow='])
            initial_url = argv[1]
            common_words = []
            ignore_urls = set()
            vectors = []
            sensitive = []
            random = False
            slow_millis = 500

            session = requests.Session()

            is_dvwa = None

            for opt, arg in opts:
                if opt == '--custom-auth':
                    if arg == 'dvwa':
                        is_dvwa = True
                    elif arg == 'bwapp':
                        is_dvwa = False

                elif opt == '--common-words':
                    for line in open(arg):
                        common_words.append(line.strip())

                elif opt == '--vectors':
                    for line in open(arg):
                        vectors.append(line.strip())

                elif opt == '--sensitive':
                    for line in open(arg):
                        sensitive.append(line)

                elif opt == '--random':
                    if arg == 'True' or arg == 'true':
                        random = True

                elif opt == '--slow':
                    slow_millis = int(arg)

            if command == 'discover' or command == 'test':
                try:
                    session.get(initial_url)
                except requests.exceptions.RequestException as e:
                    print ("Bad URL")
                    return

                links, form_inputs, url_parameters = discover(initial_url, common_words, session,
                                                              ignore_urls=ignore_urls)
                if is_dvwa is not None and is_dvwa:
                    initial_url = authenticate_dvwa(argv[1], session)
                elif is_dvwa is not None:
                    initial_url = authenticate_bwapp(argv[1], session)
                logout_url = urljoin(initial_url, "logout.php")
                ignore_urls.add(logout_url)
                new_links, new_form_inputs, new_url_parameters = discover(initial_url, common_words, session,
                                                                          ignore_urls=ignore_urls)
                links.update(new_links)
                form_inputs.update(new_form_inputs)
                url_parameters.update(new_url_parameters)
                discover_print_output(links, form_inputs, session.cookies, url_parameters)

                if command == 'test':
                    print("testing")
                    inputs = list()

                    for url in form_inputs:
                        for tag in form_inputs[url]:
                            inputs.append(FormInput(url, tag))

                    for url in links:
                        for cookie_key in session.cookies.keys():
                            inputs.append(CookieInput(url, cookie_key))

                    for url in url_parameters:
                        for parameter_key in url_parameters[url]:
                            inputs.append(URLParameterInput(url, parameter_key))

                    test(vectors, inputs, sensitive, random, slow_millis)

    except getopt.GetoptError:
        print(helpStr)


def authenticate_dvwa(url, session):
    """
    sets up the authentication for the DVWA site
    :param url: the login url of dvwa
    :param session: the current request session
    :return: the redirected url after authentication
    """
    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }

    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    user_token_tag = soup.find(lambda tag: tag.get('name') == 'user_token')
    if user_token_tag is not None and user_token_tag.get('value') is not None:
        payload["user_token"] = user_token_tag.get('value')

    return authenticate(response.url, session, payload)


def authenticate_bwapp(url, session):
    """
    sets up authentication for bwapp
    :param url: the login url of bwapp
    :param session: the current request session
    :return: the redirected url after authentication
    """
    payload = {
        "login": "bee",
        "password": "bug",
        "security_level": "0",
        "form": "submit"
    }
    return authenticate(url, session, payload)


def authenticate(login_url, session, payload):
    """
    send the authentication POST request to the sever
    :param login_url: the url of the login page
    :param session: the current request session
    :param payload: the login information
    :return: the redirected url after logging in
    """
    login_submit_response = session.post(login_url, data=payload, allow_redirects=True)
    return login_submit_response.url


def discover(url, common_words, session, ignore_urls=set()):
    """
    discovers all inputs on the specified url
    :param url: the url to start crawling from
    :param common_words: common words to use to guess web pages
    :param session: the current request session
    :param ignore_urls: urls to ignore, i.e logout.
    :return: a tuple of the found inputs
    """
    links, form_inputs, url_parameters = discover_links_and_inputs(url, urlparse(url).netloc, session,
                                                                   visited_urls=ignore_urls)
    links = set(map(sanitize_url, links))
    if common_words is not None:
            links.update(discover_guess_links(links, common_words, session))
    return links, form_inputs, url_parameters


def discover_links_and_inputs(initial_url, site, session, visited_urls=set(), form_inputs=dict(),
                              url_parameters=dict()):
    """
    discovers all references to other pages and form input fields on a webpage
    recursively visits each page that it discovers and discovers inputs on those
    :param initial_url: the starting url of the webapp
    :param site: the hostname of the server. used to not visit offsite websites
    :param session: the current request session
    :param visited_urls: the list of urls that this algorithm has already visited
    :param form_inputs: the inputs found on each page
    :param url_parameters: the query parameters discovered on a webpage
    :return: a tuple of all of the urls, form inputs, and url parameters discovered
    """
    if initial_url in visited_urls:
        return set(), dict(), dict()

    print("Downloading " + initial_url + "...", end='')

    try:
        response = session.get(initial_url)
    except Exception as e:
        print(' Exception: ' + str(e))
        return set(), dict(), dict()

    print(' Done')

    if response.status_code != 200:
        print('HTTP GET ' + initial_url + ' status is not 200')
        return set(), dict(), dict()

    if response.url in visited_urls:
        return {initial_url}, dict(), dict()
    discovered_links = {initial_url, response.url}
    print('Discovered ' + str(discovered_links))

    parameters = discover_get_url_parameters(initial_url)
    sanitized_url = sanitize_url(initial_url)
    if len(parameters) > 0:
        if sanitized_url in url_parameters.keys():
            url_parameters[sanitized_url].update(parameters)
        else:
            url_parameters[sanitized_url] = parameters

    soup = BeautifulSoup(response.content, 'html.parser')

    inputs_on_page = discover_form_inputs(soup)
    if len(inputs_on_page) > 0:
        form_inputs[initial_url] = inputs_on_page

    page_links = set()

    for page_link in soup.find_all('a'):
        url = page_link.get('href')
        url_site = urlparse(url).netloc
        if url is not None and (url_site == site or url_site == ''):
            page_links.add(urljoin(response.url, url))

    for page_link in page_links:
        child_urls, child_inputs, child_url_parameters = discover_links_and_inputs(page_link, site, session,
                                                                                   visited_urls=visited_urls.union(discovered_links),
                                                                                   form_inputs=form_inputs,
                                                                                   url_parameters=url_parameters)
        discovered_links.update(child_urls)
        form_inputs = dict(form_inputs, **child_inputs)
        url_parameters = dict(url_parameters, **child_url_parameters)

    return discovered_links, form_inputs, url_parameters


def discover_truncate_links(links):
    """
    truncates the url down to just the hostname and filepath
    :param links: list of urls to truncate
    :return: a list of the truncated urls
    """
    truncated_links = set()
    for link in links:
        l = urlparse(link)
        if l.path[-1] != "/":
            dir_path_list = l.path.split('/')[:-1]
            dir_path = reduce((lambda a, b: a + "/" + b), dir_path_list) + "/"
            truncated_links.add(l.scheme + "://" + l.netloc + dir_path)
        else:
            truncated_links.add(link)

    return truncated_links


def discover_guess_links(links, common_words, session):
    """
    guesses new urls
    :param links: truncated urls
    :param common_words: list of words to use to guess web pages
    :param session: the current request session
    :return: a set of valid webpages
    """
    truncated_urls = set(map(sanitize_url, links))
    generated_urls = generate_links(truncated_urls, common_words)
    good_urls = set()
    for url in generated_urls:
        status = discover_get_status_code(url, session)
        if status == 200:
            print("Sucessfully Guessed: " + url)
            good_urls.add(url)
        elif status == 401 or status == 403:
            generated_urls.add(generate_links([url], common_words))
    return good_urls


def discover_get_status_code(link, session):
    """
    tests the url to see if it is valid
    if the status code is 200, then it is a valid url
    :param link: url to test
    :param session: the current request session
    :return:
    """
    r = session.get(link)
    return r.status_code


def generate_links(links, common_words):
    """
    generate new urls based on the list of truncated urls and the list of common words
    :param links: the list of truncated urls
    :param common_words: list of words used to guess urls
    :return: a list of generated urls
    """
    endings = ["php", "jsp", "html", "htm", "asp", "aspx", "axd", "asx", "asmx", "ashx", "aspx", "css", "cfm", "yaws",
               "swf", "xhtml", "jhtml", "jspx", "wss", "do", "action", "js", "pl", "php4", "php3", "phtml", "py",
               "rb", "rhtml", "xml", "rss", "svg", "cgi", "dll"]
    dir_paths = discover_truncate_links(links)
    generated_links = set()

    for dir_path in dir_paths:
        for word in common_words:
            for ending in endings:
                generated_links.add(dir_path + word)
                generated_links.add(dir_path + word + '.' + ending)
    return generated_links


def discover_form_inputs(soup):
    """
    discover all form inputs on a webpage
    :param soup: the beautifulsoup object that contains the webpage
    :return: all valid form inputs
    """
    inputs = set()
    for i in soup.find_all('input'):
        if i is not None and i.get('type') != 'submit' and i.get('type') != 'button':
            copy_of_tag = i.__copy__()
            copy_of_tag.clear()
            inputs.add(copy_of_tag)
    return inputs


def sanitize_url(url):
    """
    removes queries and parameters from urls
    :param url: url to sanitize
    :return: sanitized url
    """
    if url is not None:
        index = url.find("?")
        if index != -1:
            return url[:index]
    return url


def discover_get_url_parameters(url):
    """
    gets the query and query parameters from a url
    :param url: url to get query and parameters from
    :return: url query and parameters
    """
    queries = parse_qsl(urlparse(url).query)
    keys = set()
    for key, _ in queries:
        if key == '':
            keys.add('EMPTY STRING')
        else:
            keys.add(key)
    return keys


def discover_print_output(urls, inputs, cookies, url_parameters):
    """
    print out results in a user-friendly fashion
    :param urls: the discovered urls (truncated)
    :param inputs: all form inputs discovered
    :param cookies: all cookies that were encountered
    :param url_parameters: all of the queries and query parameters found
    :return: None
    """
    print("\nFinished discovering potential attack points.")
    print("Discovered " + str(len(urls)) + " urls:")
    for url in urls:
        print("\t" + url)
    print()
    count = 0
    for val in inputs.values():
        count += len(val)
    print("Discovered " + str(count) + " inputs:")
    for key in inputs:
        print("\t" + key + ":")
        for input_tag in inputs[key]:
            print("\t\t" + str(input_tag))
    cookie_inputs = cookies.keys()
    print("Discovered " + str(len(cookie_inputs)) + " cookie inputs:")
    print(str(cookie_inputs))
    count = 0
    for val in url_parameters.values():
        count += len(val)
    print("Discovered " + str(count) + " url query inputs:")
    for url in url_parameters:
        print("\t" + url + ":")
        for query in url_parameters[url]:
            print("\t\t" + query)


def test(vectors, inputs, sensitive, random, slow):
    print("in test")
    print(vectors)
    print(sensitive)
    print(random)
    print(slow)

    for input in inputs:
        for vector in vectors:
            response = input.submit(vector)
            print('Testing the input', input, ' with the vector: ', vector)

if __name__ == "__main__":
    main(sys.argv[1:])
