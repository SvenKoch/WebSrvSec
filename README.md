# Setup:
- Install MongoDB
- Download chromedriver and matching Chrome version
- Windows only: include chromedriver binary in project directory
- Linux only: include chromedriver location in PATH
- Download Browsermob-Proxy and include in project directory (if neccessary adjust path in `app.py`)
- Create virtual environment with Python 3.7 or higher
- Install requirements from requirements.txt in virtual environment

# How to Run Developement Server in Debug Mode
- Have MongoDB daemon (mongod) running
- Activate virtual environment
- run `python app.py`