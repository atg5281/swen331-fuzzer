import getopt
import requests
from bs4 import BeautifulSoup
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
        command = ""
        arguments = argv
        if argv[0] != 'discover' and argv[0] != 'test':
            raise getopt.GetoptError("")
        else:
            command = argv[0]
            arguments = argv[2:] if len(argv) > 1 else []
            opts, args = getopt.getopt(arguments, "", ['custom-auth-string=', 'common-words=', 'vectors=', 'random=',
                                                       'slow='])
            initial_url = argv[1]
            common_words = []

            for opt, arg in opts:
                if opt == 'custom-auth-string':
                    initial_url = authenticate(argv[1])
                elif opt == 'common-words':
                    for line in open(arg):
                        common_words.append(line)
            
                
            if command == 'discover':
                discover(initial_url, common_words)
        
            
    except getopt.GetoptError:
        print(helpStr)

def authenticate(url):
    pass

def discover(url, common_words):
    links = discover_links(url, urlparse(url).netloc)
    print(links)

    for link in links:
        discover_print_inputs(link)

def discover_links(initial_url, site, discovered_urls=set()):
    print('discover_links: ' + 'initial_url = ' + initial_url);
    response = requests.get(initial_url)
    soup = BeautifulSoup(response.content, 'html.parser')
    # import pdb; pdb.set_trace()
    if response.status_code == 200 and not response.url in discovered_urls:
        found_urls = {response.url}
        
        for link in soup.find_all('a'):
            url = link.get('href')
            url_site = urlparse(url).netloc
            if not url == None and (url_site == site or url_site == ''):
                found_urls.add(urljoin(response.url, url))
            
        for url in found_urls:
            found_urls = found_urls.union(discover_links(url, site, discovered_urls.union({initial_url})))
        
        return found_urls
    else:
        return set()

def discover_guess_links(base_url, common_words):
    return {}

def discover_print_inputs(link):
    pass


if __name__ == "__main__":
    main(sys.argv[1:])
