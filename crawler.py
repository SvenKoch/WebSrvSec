import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, \
    Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from browsermobproxy import Server


def save_results(results):
    # TODO
    print(results)


def determine_up_to_date_third_party_lib_score():
    # TODO WhatsWeb Scan
    return -1


def determine_js_inclusion_cross_domain_existence_score():
    # TODO
    return -1


# return 0 if no cross-origin-resources are integrity-checked
# return 1 if some cross-origin-resources are integrity-checked
# return 2 if all cross-origin-resources are integrity-checked
def determine_sri_score(response):
    # TODO consider require-sri-for CSP policy
    soup = BeautifulSoup(response.text)
    cors_script_and_link_tags = soup.find_all(['script', 'link'], crossorigin=True)
    sri_protected_cors_script_and_link_tags = soup.find_all(['script', 'link'], crossorigin=True, integrity=True)

    if set(cors_script_and_link_tags) == set(sri_protected_cors_script_and_link_tags):
        return 2
    if sri_protected_cors_script_and_link_tags:
        return 1
    return 0


# return 0 if mixed content was detected
# return 1 otherwise
def determine_mixed_content_score(har_entries):
    # TODO consider upgrade-insecure-requests CSP policy
    for entry in har_entries:
        if urlparse(entry['request']['url']).scheme.casefold() != 'https'.casefold():
            return 0
    return 1


def determine_up_to_date_server_software_score():
    # TODO WhatsWeb Scan
    return -1


def determine_cache_control_score(response):
    cache_control = response.headers['Cache-Control']
    pragma = response.headers['Pragma']
    # mandatory
    private_directive = False
    no_store_directive = False
    # bonus
    no_cache_directive = False
    must_revalidate = False
    max_age_0 = False
    pragma_no_cache = False

    soup = BeautifulSoup(response.text)
    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile('^cache-control$', re.I)}):
        match = re.search('content="(.+)"', meta_tag, re.I)
        if match:
            meta_content = match.group(1)
            if cache_control:
                cache_control = f'{cache_control}, {meta_content}'
            else:
                cache_control = meta_content

    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile('^pragma$', re.I)}):
        match = re.search('content="(.+)"', meta_tag, re.I)
        if match:
            meta_content = match.group(1)
            if pragma:
                pragma = f'{pragma}, {meta_content}'
            else:
                pragma = meta_content

    if cache_control:
        if 'private'.casefold() in cache_control.casefold():
            private_directive = True
        if 'no-store'.casefold() in cache_control.casefold():
            no_store_directive = True
        if 'no-cache'.casefold() in cache_control.casefold():
            no_cache_directive = True
        if 'must-revalidate'.casefold() in cache_control.casefold():
            must_revalidate = True
        if 'max-age=0'.casefold() in cache_control.casefold():
            max_age_0 = True
    if pragma and pragma.casefold() == 'no-cache'.casefold():
        pragma_no_cache = True

    # TODO scoring
    return -1


def determine_referrer_policy_score(response, har_entries):
    # analyze the server’s response headers
    referrer_policy_header = response.headers['Referrer-Policy']
    if referrer_policy_header:
        referrer_policy_header = referrer_policy_header.casefold()
        if referrer_policy_header == 'no-referrer'.casefold():
            pass
        if referrer_policy_header == 'no-referrer-when-downgrade'.casefold():
            pass
        if referrer_policy_header == 'origin'.casefold():
            pass
        if referrer_policy_header == 'origin-when-cross-origin'.casefold():
            pass
        if referrer_policy_header == 'same-origin'.casefold():
            pass
        if referrer_policy_header == 'strict-origin'.casefold():
            pass
        if referrer_policy_header == 'strict-origin-when-cross-origin'.casefold():
            pass
        if referrer_policy_header == 'unsafe-url'.casefold():
            pass

    # but also whether the Referer HTTP request headers of the web application’s outgoing requests
    # to cross-domains contain the origin URLs
    url_leaked_in_cross_domain_request = False
    for entry in har_entries:
        for request_header in entry['request']['headers']:
            if request_header['name'].casefold() == 'Referer'.casefold():
                if urlparse(entry['request']['url']).hostname != urlparse(response.url).hostname:
                    if response.url in request_header['value']:
                        url_leaked_in_cross_domain_request = True
                        break
        if url_leaked_in_cross_domain_request:
            break

    # parse the website’s source for meta tags containing referrer policies
    soup = BeautifulSoup(response.text)
    meta_policy = ''
    for meta_tag in soup.find_all('meta', attrs={'name': re.compile('^referrer$', re.I)}):
        match = re.search('content="(.+)"', meta_tag, re.I)
        if match:
            if meta_policy:
                # TODO handle more than one meta_policy
                pass
            meta_policy = match.group(1)

    # TODO scoring
    return -1


# return 0 if no csrf token was found but a form is present
# return 1 if no csrf token was found but no form was present
# return 2 if csrf token was found
def determine_csrf_score(response):
    # long alphanumeric string in hidden input field or cookie
    # keywords: csrf, nonce, token
    # negative cookie keyword: session

    # csrf_token_found = False
    csrf_keywords = ['csrf', 'token', 'nonce']
    token_regex = '[a-zA-Z0-9]{20,}'

    for cookie in response.cookies:
        if any(keyword.casefold() in cookie.name.casefold() for keyword in csrf_keywords):
            if not 'session'.casefold() in cookie.name.casefold():
                if re.search(token_regex, cookie.value, re.I):
                    # csrf_token_found = True
                    return 2

    soup = BeautifulSoup(response.text)
    hidden_inputs = soup.find_all('input', type='hidden')
    for hidden_input in hidden_inputs:
        if any(keyword.casefold() in hidden_input.casefold() for keyword in csrf_keywords):
            if re.search(token_regex, hidden_input, re.I):
                # csrf_token_found = True
                return 2

    if soup.find('form'):
        return 0

    return 1


# return -1 on timeout
# return 0 if no Content Security Policy is found
# return 1 if evaluation of CSP yields high severity finding(s)
# return 2 if evaluation of CSP yields medium severity finding(s)
# return 3 if evaluation of CSP yields possible high severity finding(s)
# return 4 if evaluation of CSP yields possible medium severity finding(s)
# return 5 if evaluation of CSP yields no (possibly) negative findings
def determine_csp_score(hostname):
    # TODO return if upgrade-insecure-requests CSP policy is set
    # TODO return if require-sri-for CSP policy is set
    driver = webdriver.Chrome()
    driver.get('https://csp-evaluator.withgoogle.com')
    textarea = driver.find_element_by_tag_name('textarea')
    driver.find_element_by_class_name('csp_input_box').click()
    textarea.send_keys(f'https://{hostname}')
    button = driver.find_element_by_id('check')
    button.click()
    try:
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CLASS_NAME, 'evaluated-csp')))
        evaluated_csp = driver.find_element_by_class_name('evaluated-csp')
        evaluated_csp_html = evaluated_csp.get_attribute('innerHTML')
    except TimeoutException:
        return -1
    except UnexpectedAlertPresentException:
        return 0
    finally:
        driver.quit()
    if 'data-tooltip="High severity finding"' in evaluated_csp_html:
        return 1
    if 'data-tooltip="Medium severity finding"' in evaluated_csp_html:
        return 2
    if 'data-tooltip="Possible high severity finding"' in evaluated_csp_html:
        return 3
    if 'data-tooltip="Possible medium severity finding"' in evaluated_csp_html:
        return 4
    return 5


# return 0 if crossorigin="use-credentials" was found in HTML source
# return 1 otherwise
def determine_cors_score(response, har_entries):
    for entry in har_entries:
        for request_header in entry['request']['headers']:
            if request_header['name'].casefold() == 'Origin'.casefold():
                if request_header['value'].casefold() != 'None'.casefold():
                    # Origin header is set, so this is either a CORS or a POST request
                    # TODO what do we do with this information?
                    pass

    soup = BeautifulSoup(response.text)
    if soup.find_all(True, crossorigin=re.compile('^use-credentials$', re.I)):
        return 0
    return 1


# return 0 if Access-Control-Allow-Origin header is set to *
# return 1 if Access-Control-Allow-Origin header is present
# return 2 if Access-Control-Allow-Origin header is absent
# add 3 for X-Permitted-Cross-Domain-Policies: none or if neither crossdomain.xml nor clientaccesspolicy.xml are present
def determine_cors_policy_score(response):
    access_control_allow_origin_header = response.headers['Access-Control-Allow-Origin']
    x_permitted_cross_domain_policies_header = response.headers['X-Permitted-Cross-Domain-Policies']
    x_permitted_cross_domain_policies_set_to_none = False
    lazy_wildcard = False
    crossdomain_xml_present = False
    clientaccesspolicy_xml_present = False
    if access_control_allow_origin_header and access_control_allow_origin_header == '*':
        lazy_wildcard = True
    if x_permitted_cross_domain_policies_header \
            and x_permitted_cross_domain_policies_header.casefold() == 'none'.casefold():
        x_permitted_cross_domain_policies_set_to_none = True

    hostname = urlparse(response.url).hostname
    crossdomain_xml = requests.get(f'https://{hostname}/crossdomain.xml')
    clientaccesspolicy_xml = requests.get(f'https://{hostname}/clientaccesspolicy.xml')

    if crossdomain_xml.status_code == 200:
        crossdomain_xml_present = True
    if clientaccesspolicy_xml.status_code == 200:
        clientaccesspolicy_xml_present = True

    # TODO nice to have: analyze XML files if present

    if lazy_wildcard:
        score = 0
    elif access_control_allow_origin_header:
        score = 1
    else:
        score = 2

    if x_permitted_cross_domain_policies_set_to_none or \
            (not crossdomain_xml_present and not clientaccesspolicy_xml_present):
        score += 3
    return score


# return 14 if all cookies contain the Secure, HttpOnly and SameSite=Strict directives and are set via header
# subtract 1 for missing SameSite directive
# subtract 2 for missing HttpOnly directive
# subtract 4 for missing Secure directive
# subtract 7 for cookies set via meta tag in HTML source
def determine_cookie_security_score(response):
    cookies_set_via_meta_tags = False
    secure = True
    http_only = True
    same_site = True
    for cookie in response.cookies:
        if not cookie.secure:
            secure = False
        if not cookie.has_nonstandard_attr('HttpOnly'):
            http_only = False
        if not cookie.get_nonstandard_attr('SameSite', default='').casefold() == 'Strict'.casefold():
            same_site = False

    soup = BeautifulSoup(response.text)
    set_cookie_metas = soup.find_all('meta', attrs={"http-equiv": re.compile("^Set-Cookie$", re.I)})
    if set_cookie_metas:
        cookies_set_via_meta_tags = True
    for cookie in set_cookie_metas:
        match = re.search('content="(.*)"', cookie, re.I)
        if match:
            content = match.group(1)
            split_content = [x.casefold() for x in content.split(';')]
            if 'Secure'.casefold() not in split_content:
                secure = False
            if 'HttpOnly'.casefold() not in split_content:
                http_only = False
            if 'SameSite=Strict'.casefold() not in split_content:
                same_site = False

    score = 14
    if cookies_set_via_meta_tags:
        score -= 7
    if not secure:
        score -= 4
    if not http_only:
        score -= 2
    if not same_site:
        score -= 1
    return score


# return 0 if Expect-CT header is absent or max-age is missing
# return 1 if in report-only mode
# return 2 if in enforce(-and-report)-mode
def determine_expect_ct_score(response_headers):
    expect_ct_header = response_headers('Expect-CT')
    if expect_ct_header is None:
        return 0
    if re.search('max-age=(\\d+)', expect_ct_header, flags=re.I) is None:
        return 0
    if 'enforce'.casefold() in expect_ct_header.casefold().split(','):
        return 2
    if 'report-uri="'.casefold() in expect_ct_header.casefold():
        return 1
    return 0


# return 1 if X-Download-Options: is set to noopen
# return 0 otherwise
def determine_x_download_options_score(response_headers):
    download_options_header = response_headers['X-Download-Options']
    if download_options_header is None:
        return 0
    if 'noopen'.casefold() == download_options_header.casefold():
        return 1
    else:
        return 0


# return 1 if X-Frame-Options is set to DENY or SAMEORIGIN
# return 0 otherwise
def determine_x_frame_options_score(response_headers):
    frame_options_header = response_headers['X-Frame-Options']
    if frame_options_header is None:
        return 0
    if 'DENY'.casefold() == frame_options_header.casefold() \
            or 'SAMEORIGIN'.casefold() == frame_options_header.casefold():
        return 1
    else:
        return 0


# return 0 if X-XSS-Protection is set to 0
# return 1 if X-XSS-Protection header is absent
# return 2 if X-XSS-Protection is set to 1
def determine_x_xss_protection_score(response_headers):
    xss_protection_header = response_headers['X-XSS-Protection']
    if xss_protection_header is None:
        return 1
    if '0' == xss_protection_header[0]:
        return 0
    if '1' == xss_protection_header[0]:
        return 2


# return 1 if X-Content-Type-Options is set to nosniff
# return 0 otherwise
def determine_x_content_type_options_score(response_headers):
    content_type_options_header = response_headers['X-Content-Type-Options']
    if content_type_options_header is None:
        return 0
    if 'nosniff'.casefold() == content_type_options_header.casefold():
        return 1


# return 0 if no valid HPKP response header is present
# return 1 if HPKP response header is present
# add 1 if max-age is between 15 and 120 days
# add 2 for includeSubDomains option
def determine_hpkp_score(response_headers):
    hpkp_header = response_headers['Public-Key-Pins']
    if hpkp_header is None:
        return 0
    if 'pin-sha256'.casefold() not in hpkp_header.casefold():
        return 0

    max_age_match = re.search('max-age=(\\d+)', hpkp_header, flags=re.I)
    if max_age_match is None:
        return 0
    max_age = int(max_age_match.group(1))
    if max_age < 15*24*60*60 or max_age > 120*24*60*60:
        score = 1
    else:
        score = 2

    if 'includeSubDomains'.casefold() in hpkp_header.casefold():
        score += 2

    return score


# return 0 if no valid HSTS response header is present
# return 1 if HSTS response header is present but max-age is lower than 120 days
# return 2 if HSTS response headers is present and max-age is higher than 120 days
# add 2 for includeSubdomain option
# add another 2 for preload option (includeSubdomain is mandatory in this case)
def determine_hsts_score(response_headers):
    hsts_header = response_headers['Strict-Transport-Security']
    if hsts_header is None:
        return 0

    max_age_match = re.search('max-age=(\\d+)', hsts_header, flags=re.I)
    if max_age_match is None:
        return 0
    max_age = int(max_age_match.group(1))
    if max_age < 120*24*60*60:
        score = 1
    else:
        score = 2

    if 'includeSubDomains'.casefold() in hsts_header.casefold():
        score += 2
        if 'preload'.casefold() in hsts_header.casefold():
            score += 2

    return score


def get_ssl_server_info(hostname):
    try:
        server_tester = ServerConnectivityTester(hostname=hostname)
        server_info = server_tester.perform(network_timeout=10)
    except ServerConnectivityError as e:
        # Could not establish an SSL connection to the server
        raise RuntimeError(f'Could not connect to {e.server_info.hostname}: {e.error_message}')

    return server_info


def get_supported_tls_cipher_suites(hostname):
    server_info = get_ssl_server_info(hostname)
    concurrent_scanner = ConcurrentScanner()
    concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv10ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv11ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv13ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, FallbackScsvScanCommand())

    for scan_result in concurrent_scanner.get_results():
        # A scan command can fail (as a bug); it is returned as a PluginRaisedExceptionResult
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            raise RuntimeError(f'Scan command failed: {scan_result.scan_command.get_title()}')

        if isinstance(scan_result.scan_command, Sslv20ScanCommand):
            accepted_ssl2 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_ssl2 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_ssl2 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, Sslv30ScanCommand):
            accepted_ssl3 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_ssl3 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_ssl3 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, Tlsv10ScanCommand):
            accepted_tls10 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_tls10 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_tls10 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, Tlsv11ScanCommand):
            accepted_tls11 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_tls11 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_tls11 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            accepted_tls12 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_tls12 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_tls12 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, Tlsv13ScanCommand):
            accepted_tls13 = [cipher.name for cipher in scan_result.accepted_cipher_list]
            denied_tls13 = [cipher.name for cipher in scan_result.rejected_cipher_list]
            errored_tls13 = [cipher.name for cipher in scan_result.errored_cipher_list]
        if isinstance(scan_result.scan_command, FallbackScsvScanCommand):
            supports_fallback_scsv = scan_result.supports_fallback_scsv

    return {
        'accepted_ssl2': accepted_ssl2,
        'denied_ssl2': denied_ssl2,
        'errored_ssl2': errored_ssl2,
        'accepted_ssl3': accepted_ssl3,
        'denied_ssl3': denied_ssl3,
        'errored_ssl3': errored_ssl3,
        'accepted_tls10': accepted_tls10,
        'denied_tls10': denied_tls10,
        'errored_tls10': errored_tls10,
        'accepted_tls11': accepted_tls11,
        'denied_tls11': denied_tls11,
        'errored_tls11': errored_tls11,
        'accepted_tls12': accepted_tls12,
        'denied_tls12': denied_tls12,
        'errored_tls12': errored_tls12,
        'accepted_tls13': accepted_tls13,
        'denied_tls13': denied_tls13,
        'errored_tls13': errored_tls13,
        'supports_fallback_scsv': supports_fallback_scsv
    }


# return -1 if no accepted cipher suites were identified with any TLS version
# return 0 if SSL 2.0 or 3.0 cipher suites are supported by the server
# return 1 if weak TLS 1.0 or 1.1 cipher suites are supported by the server
# or the server is missing TLS Fallback Signaling Cipher Suite Value support
# return 2 for TLS 1.0 or 1.1 otherwise
# return 3 for TLS 1.2+
def determine_tls_score(hostname):
    supported_cipher_suites = get_supported_tls_cipher_suites(hostname)
    if supported_cipher_suites['accepted_ssl2'] or supported_cipher_suites['accepted_ssl3']:
        return 0
    if supported_cipher_suites['accepted_tls10'] or supported_cipher_suites['accepted_tls11']:
        weak_cipher_keywords = ['NULL', 'MD5', 'RC4', '3DES', 'EXPORT', 'anon']
        for accepted_suites in (supported_cipher_suites['accepted_tls10'] + supported_cipher_suites['accepted_tls11']):
            if not supported_cipher_suites['supports_fallback_scsv'] \
                    or any(x in accepted_suites for x in weak_cipher_keywords):
                return 1
        return 2
    if supported_cipher_suites['accepted_tls12'] or supported_cipher_suites['accepted_tls13']:
        return 3
    return -1


# return 0 if site does not redirect to https
# return 4 for perfect redirection
# subtract 2 if initial redirect is to different host
# subtract 1 if redirection chain contains http site
def determine_http_redirection_score(response):
    score = 4
    if urlparse(response.url).scheme != 'https':
        return 0
    # (1) Sites should avoid initial redirections to a different host, as this prevents HSTS from being set.
    initial_redirect = response.history[0]
    hostname_request = urlparse(initial_redirect.url).hostname
    hostname_redirect = urlparse(initial_redirect.headers['Location']).hostname
    if hostname_redirect != hostname_request:
        score -= 2

    # (2) In case of multiple redirections (Redirection Chain), every single redirection has to use HTTPS,
    # which prevents the traffic from being intercepted in cleartext.
    for redirect in response.history:
        if urlparse(redirect.headers['Location']).scheme != 'https':
            score -= 1
            break
    return score


def analyze(hostname):
    # TODO set user-agent
    response = requests.get(f'http://{hostname}', timeout=10)
    # TODO handle timeout
    redirected_hostname = urlparse(response.url).hostname
    # phase 0
    http_redirection_score = determine_http_redirection_score(response)
    # phase 1
    tls_score = determine_tls_score(redirected_hostname)
    # phase 2
    response = requests.get(f'https://{redirected_hostname}', timeout=10)
    # TODO handle timeout
    response_headers = response.headers
    hsts_score = determine_hsts_score(response_headers)
    hpkp_score = determine_hpkp_score(response_headers)
    x_content_type_options_score = determine_x_content_type_options_score(response_headers)
    x_xss_protection_score = determine_x_xss_protection_score(response_headers)
    x_frame_options_score = determine_x_frame_options_score(response_headers)
    x_download_options_score = determine_x_download_options_score(response_headers)
    expect_ct_score = determine_expect_ct_score(response_headers)
    # phase 3
    cookie_security_score = determine_cookie_security_score(response)
    cors_policy_score = determine_cors_policy_score(response)
    csp_score = determine_csp_score(redirected_hostname)
    csrf_score = determine_csrf_score(response)

    server = Server()
    server.start()
    proxy = server.create_proxy()

    options = webdriver.ChromeOptions()
    options.add_argument(f'--proxy-server={proxy.proxy}')
    driver = webdriver.Chrome(chrome_options=options)
    proxy.new_har()
    driver.get(f'https://{redirected_hostname}')
    server.stop()
    driver.quit()

    har_entries = proxy.har['log']['entries']
    cors_score = determine_cors_score(response, har_entries)
    referrer_policy_score = determine_referrer_policy_score(response, har_entries)
    cache_control_score = determine_cache_control_score(response)
    up_to_date_server_software_score = determine_up_to_date_server_software_score()
    # phase 4
    mixed_content_score = determine_mixed_content_score(har_entries)
    sri_score = determine_sri_score(response)
    js_inclusion_cross_domain_existence_score = determine_js_inclusion_cross_domain_existence_score()
    up_to_date_third_party_lib_score = determine_up_to_date_third_party_lib_score()

    results = {
        'hostname': hostname,
        'http_redirection_score': http_redirection_score,
        'tls_score': tls_score,
        'hsts_score': hsts_score,
        'hpkp_score': hpkp_score,
        'x_content_type_options_score': x_content_type_options_score,
        'x_xss_protection_score': x_xss_protection_score,
        'x_frame_options_score': x_frame_options_score,
        'x_download_options_score': x_download_options_score,
        'expect_ct_score': expect_ct_score,
        'cookie_security_score': cookie_security_score,
        'cors_policy_score': cors_policy_score,
        'cors_score': cors_score,
        'csp_score': csp_score,
        'csrf_score': csrf_score,
        'referrer_policy_score': referrer_policy_score,
        'cache_control_score': cache_control_score,
        'up_to_date_server_software_score': up_to_date_server_software_score,
        'mixed_content_score': mixed_content_score,
        'sri_score': sri_score,
        'js_inclusion_cross_domain_existence_score': js_inclusion_cross_domain_existence_score,
        'up_to_date_third_party_lib_score': up_to_date_third_party_lib_score
    }
    save_results(results)


if __name__ == '__main__':
    analyze('google.com')
    analyze('github.com')
    analyze('vr-bank.de')
    analyze('sparkasse.de')
    # analyze('sparkasse-nuernberg.de')
