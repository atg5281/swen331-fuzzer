import getopt
import sys

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
            arguments = argv[1:] if len(argv) > 1 else []
        opts, args = getopt.getopt(arguments, "", ['custom-auth-string=', 'common-words=', 'vectors=', 'random=',
                                                   'slow='])
    except getopt.GetoptError:
        print(helpStr)

if __name__ == "__main__":
    main(sys.argv[1:])
