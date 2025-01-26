import requests
from bs4 import BeautifulSoup

# Function to check for SQL Injection vulnerability
def check_sql_injection(url):
    sql_payloads = ["'", '"', "' OR '1'='1", '" OR "1"="1']
    vulnerable = False
    for payload in sql_payloads:
        full_url = f"{url}{payload}"
        response = requests.get(full_url)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            vulnerable = True
            print(f"Possible SQL Injection vulnerability detected with payload: {payload}")
    return vulnerable

# Function to check for XSS vulnerability
def check_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", '"><script>alert(1)</script>']
    vulnerable = False
    for payload in xss_payloads:
        full_url = f"{url}{payload}"
        response = requests.get(full_url)
        if payload in response.text:
            vulnerable = True
            print(f"Possible XSS vulnerability detected with payload: {payload}")
    return vulnerable

# Function to parse forms and check for vulnerabilities
def scan_forms(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        form_data = {}
        for input in inputs:
            input_name = input.get('name')
            input_value = input.get('value', 'test')
            form_data[input_name] = input_value

        if method == 'post':
            response = requests.post(url + action, data=form_data)
        else:
            response = requests.get(url + action, params=form_data)
        
        # Check for vulnerabilities in the form response
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"Possible SQL Injection vulnerability detected in form action: {action}")
        if "<script>alert('XSS')</script>" in response.text:
            print(f"Possible XSS vulnerability detected in form action: {action}")