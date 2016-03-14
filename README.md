# swen331-fuzzer

Project Information:

Language: python 3
External Libraries: Request, BeautifulSoup4

Contact information:

James De Ricco - jcd7042@rit.edu

Austin Gardner - atg5281@rit.edu

Nick James - nxj2348@rit.edu


INSTALL:

Python 3+ with pip

pip install requests
pip install beautifulsoup4

From the command line, the basic structure of the command is:
fuzz [discover | test] url OPTIONS

Commands:
	discover: Outputs a comprehensive, human-readable list of all discovered inputs to the system.
	test: Discover all inputs, then attempt a list of exploit vectors on those inputs. Reports potential vulnerabilities.

Options:
	--custom-auth=string: Signal that the fuzzer should use hard-coded authentication for a specific application. Optional.
Discover options:
	--common-words=file    Newline-delimited file of common words to be used in page guessing and input guessing. Required.


  Test options:
	--vectors=file: Newline-delimited file of common exploits to vulnerabilities. Required.
	--sensitive=file: Newline-delimited file data that should never be leaked. It's assumed that this data is in the application's database (e.g. test data), but is not reported in any response. Required.
	--random=[true|false]  When off, try each input to each page systematically.  When on, choose a random page, then a random input field and test all vectors. Default: false.
	--slow=500: Number of milliseconds considered when a response is considered "slow". Default is 500 milliseconds

Examples:
	# Discovers all inputs on the url: http://127.0.0.1/dvwa/
	discover http://127.0.0.1/dvwa/ --custom-auth=dvwa
	# Discover and Test inputs on the url: http://127.0.0.1/dvwa/
	test http://127.0.0.1/dvwa/ --custom-auth=dvwa –random=false –slow=600 –vectors=vectors.txt
