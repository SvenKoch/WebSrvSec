# WebSrvSec
This is the repo containing the source code of [WebSrvSec](https://websrvsec.cs.fau.de), a web application to automatically assess security and privacy features of websites.
It was developed as my Master's project at the [Chair of IT Security Infrastructures at FAU](https://www.cs1.tf.fau.de/).

# Setup
- Install MongoDB
- Download chromedriver and matching Chrome version
- Windows only: include chromedriver binary in project directory
- Linux only: include chromedriver location in PATH
- Download Browsermob-Proxy and include in project directory (if neccessary adjust path in `scanner.py`)
- Create virtual environment with Python 3.7 or higher
- Install requirements from requirements.txt in virtual environment

# How to Run Developement Server in Debug Mode
- Have MongoDB daemon (mongod) running
- Activate virtual environment
- run `python app.py`

# Credits
Third party lib detection by [Library Detector For Chrome](https://github.com/johnmichel/Library-Detector-for-Chrome)
