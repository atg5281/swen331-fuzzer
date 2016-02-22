from bs4 import BeautifulSoup
import copy
import getopt
from functools import reduce
import requests
import sys
from urllib.parse import urljoin, urlparse

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
    try:
        if argv[0] != 'discover' and argv[0] != 'test':
            raise getopt.GetoptError("")
        else:
            command = argv[0]
            arguments = argv[2:] if len(argv) > 1 else []
            opts, args = getopt.getopt(arguments, "", ['custom-auth=', 'common-words=', 'vectors=', 'random=',
                                                       'slow='])
            initial_url = argv[1]
            common_words = []

            session = requests.Session()

            for opt, arg in opts:
                if opt == '--custom-auth':
                    initial_url = authenticate(argv[1], session)
                elif opt == '--common-words':
                    for line in open(arg):
                        common_words.append(line)

            if command == 'discover':
                discover(initial_url, common_words, session)

    except getopt.GetoptError:
        print(helpStr)


def authenticate(url, session):
    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }

    user_token_tag = soup.find(lambda tag: tag.get('name') == 'user_token')
    if user_token_tag is not None and user_token_tag.get('value') is not None:
        payload["user_token"] = user_token_tag.get('value')

    login_submit_response = session.post(response.url, data=payload, allow_redirects=True)
    return login_submit_response.url


def discover(url, common_words, session):
    links, form_inputs = discover_links_and_inputs(url, urlparse(url).netloc, session)
    if common_words is not None:
        links = links.union(set(discover_guess_links(links, common_words, session)))
    print('Discovered ' + str(len(links)) + ' URLs:')
    links = list(map(sanitize_url, links))
    print(links)
    print()
    print('Discovered ' + str(len(form_inputs)) + ' Form Inputs:')
    print(form_inputs)


def discover_links_and_inputs(initial_url, site, session, visited_urls=set(), form_inputs=dict()):
    if initial_url in visited_urls:
        return set(), dict()

    print("discover_links_and_inputs: Downloading " + initial_url + "...", end='')
    response = session.get(initial_url)
    print(' Done')

    if response.status_code != 200:
        print('discover_links_and_inputs: HTTP GET ' + initial_url + ' status is not 200')
        return set(), dict()

    if response.url in visited_urls:
        return {initial_url}, dict()
    discovered_links = {initial_url, response.url}
    print('discover_links_and_inputs: Discovered ' + str(discovered_links))

    soup = BeautifulSoup(response.content, 'html.parser')
    form_inputs[initial_url] = discover_form_inputs(soup)

    page_links = set()

    for page_link in soup.find_all('a'):
        url = page_link.get('href')
        url_site = urlparse(url).netloc
        if url is not None and (url_site == site or url_site == ''):
            page_links.add(urljoin(response.url, url))

    for page_link in page_links:
        child_urls, child_inputs = discover_links_and_inputs(page_link, site, session, visited_urls=visited_urls.union(discovered_links), form_inputs=form_inputs)
        discovered_links.update(child_urls)
        form_inputs = dict(form_inputs, **child_inputs)

    return discovered_links, form_inputs


def discover_truncate_links(links):
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
    return filter((lambda link: test_link(link, session)), generate_links(links, common_words))


def test_link(link, session):
    r = session.get(link)
    return r.status_code == 200


def generate_links(links, common_words):
    endings = ["php", "jsp", "html", "htm", "asp", "aspx", "axd", "asx", "asmx", "ashx", "aspx", "css", "cfm", "yaws",
               "swf", "xhtml", "jhtml", "jspx", "wss", "do", "action", "js", "pl", "php4", "php3", "phtml", "py",
               "rb", "rhtml", "xml", "rss", "svg", "cgi", "dll"]
    dir_paths = discover_truncate_links(links)
    generated_links = set()

    for dir_path in dir_paths:
        for word in common_words:
            for ending in endings:
                generated_links.add(dir_path + word + ending)

    return generated_links


def discover_form_inputs(soup):
    inputs = set()
    for i in soup.find_all('input'):
        if i.get('type') != 'submit' and i.get('type') != 'button' and i is not None:
            temp = copy.deepcopy(i)
            temp.clear()
            inputs.add(temp)
    return inputs


def sanitize_url(url):
    if url is not None:
        index = url.find("?")
        if index != -1:
            return url[:index]
    return url


if __name__ == "__main__":
    main(sys.argv[1:])
