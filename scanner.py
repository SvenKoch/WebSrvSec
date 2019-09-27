import datetime
import re
import time
from urllib.parse import urlparse

import requests
import whois
from browsermobproxy import Server
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

from results import CrossDomainExistenceResult, SriResult, MixedContentResult, LeakingServerSoftwareInfoResult, \
    ThirdPartyLibsResult, SuccessResult, CacheControlResult, ReferrerPolicyResult, CsrfResult, Severity, \
    CspResult, \
    CorsResult, CorsPolicyResult, CookieSecurityResult, ExpectCtResult, XDownloadOptionsResult, XFrameOptionsResult, \
    XXssProtectionResult, XContentTypeOptionsResult, HpkpResult, HstsResult, TlsResult, HttpRedirectionResult, \
    ErrorResult

USER_AGENT_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'
USER_AGENT_IE = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'


def analyze_cross_domain_existence(response_url, har_entries):
    hostname = urlparse(response_url).hostname
    query_to_non_existing_domain = False
    non_existing_domains = []
    checked_domains = []
    for entry in har_entries:
        url = entry['request']['url']
        entry_hostname = urlparse(url).hostname
        if entry_hostname != hostname and entry_hostname not in checked_domains:
            try:
                whois.whois(url)
                checked_domains.append(entry_hostname)
            except whois.parser.PywhoisError:
                query_to_non_existing_domain = True
                non_existing_domains.append(url)
            except ConnectionResetError:
                # probably requests are too frequent, wait for a bit and try again
                try:
                    time.sleep(1)
                    whois.whois(url)
                    checked_domains.append(entry_hostname)
                except whois.parser.PywhoisError:
                    query_to_non_existing_domain = True
                    non_existing_domains.append(url)

    return CrossDomainExistenceResult(query_to_non_existing_domain=query_to_non_existing_domain,
                                      non_existing_domains=non_existing_domains)


def analyze_sri_protection(soup):
    cors_script_and_link_tags = soup.find_all(['script', 'link'], crossorigin=True)
    cors_script_and_link_tags = [str(x) for x in cors_script_and_link_tags]
    protected_cors_script_and_link_tags = soup.find_all(['script', 'link'], crossorigin=True, integrity=True)
    protected_cors_script_and_link_tags = [str(x) for x in protected_cors_script_and_link_tags]
    unprotected_cors_script_and_link_tags = \
        list(set(cors_script_and_link_tags).difference(protected_cors_script_and_link_tags))

    return SriResult(protected_cors_script_and_link_tags=protected_cors_script_and_link_tags,
                     unprotected_cors_script_and_link_tags=unprotected_cors_script_and_link_tags)


def analyze_mixed_content(har_entries):
    outgoing_http_request_urls = []
    for entry in har_entries:
        url = entry['request']['url']
        if urlparse(url).scheme.casefold() != 'https'.casefold():
            outgoing_http_request_urls.append(url)
    return MixedContentResult(outgoing_http_request_urls=outgoing_http_request_urls)


def analyze_third_party_libs(third_party_libs):
    for lib in third_party_libs:
        if lib['version'] is None:
            lib['version'] = 'unknown'
    return ThirdPartyLibsResult(third_party_libs=third_party_libs)


def analyze_leaking_server_software_info(response_headers):
    server_header = response_headers.get('Server')
    x_powered_by_header = response_headers.get('X-Powered-By')
    server_header_present = False
    server_header_contains_version = False
    x_powered_by_header_present = False
    x_powered_by_header_contains_version = False
    if server_header:
        server_header_present = True
        if re.search(r'/\d', server_header, re.I):
            server_header_contains_version = True
    if x_powered_by_header:
        x_powered_by_header_present = True
        if re.search(r'/\d', x_powered_by_header, re.I):
            x_powered_by_header_contains_version = True
    return LeakingServerSoftwareInfoResult(server_header_present=server_header_present,
                                           server_header_contains_version=server_header_contains_version,
                                           x_powered_by_header_present=x_powered_by_header_present,
                                           x_powered_by_header_contains_version=x_powered_by_header_contains_version)


def analyze_cache_control(response_headers, soup):
    cache_control = response_headers.get('Cache-Control')
    pragma = response_headers.get('Pragma')
    # mandatory
    private_directive = False
    no_store_directive = False
    # bonus
    no_cache_directive = False
    must_revalidate = False
    max_age_0 = False
    pragma_no_cache = False

    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile('^cache-control$', re.I)}):
        match = re.search('content="(.+)"', str(meta_tag), re.I)
        if match:
            meta_content = match.group(1)
            if cache_control:
                cache_control = f'{cache_control}, {meta_content}'
            else:
                cache_control = meta_content

    for meta_tag in soup.find_all('meta', attrs={'http-equiv': re.compile('^pragma$', re.I)}):
        match = re.search('content="(.+)"', str(meta_tag), re.I)
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
    if pragma and 'no-cache'.casefold() in pragma.casefold():
        pragma_no_cache = True

    return CacheControlResult(private_directive=private_directive,
                              no_store_directive=no_store_directive,
                              no_cache_directive=no_cache_directive,
                              must_revalidate=must_revalidate,
                              max_age_0=max_age_0,
                              pragma_no_cache=pragma_no_cache)


def analyze_referrer_policy(response_headers, response_url, soup, har_entries):
    # analyze the server’s response headers
    referrer_policy_header = response_headers.get('Referrer-Policy', '').casefold()

    # but also whether the Referer HTTP request headers of the web application’s outgoing requests
    # to cross-domains contain the origin URLs
    url_leaked_in_cross_domain_request = False
    for entry in har_entries:
        for request_header in entry['request']['headers']:
            if request_header['name'].casefold() == 'Referer'.casefold():
                if urlparse(entry['request']['url']).hostname != urlparse(response_url).hostname:
                    if response_url in request_header['value']:
                        url_leaked_in_cross_domain_request = True
                        break
        if url_leaked_in_cross_domain_request:
            break

    # parse the website’s source for meta tags containing referrer policies
    meta_policy = ''
    multiple_meta_policies = False
    for meta_tag in soup.find_all('meta', attrs={'name': re.compile('^referrer$', re.I)}):
        match = re.search('content="(.+)"', str(meta_tag), re.I)
        if match:
            if meta_policy and match.group(1) != meta_policy:
                multiple_meta_policies = True
                meta_policy = ''
                break
            meta_policy = match.group(1)

    return ReferrerPolicyResult(referrer_policy_header=referrer_policy_header,
                                url_leaked_in_cross_domain_request=url_leaked_in_cross_domain_request,
                                meta_policy=meta_policy,
                                multiple_meta_policies=multiple_meta_policies)


def analyze_csrf(response_cookies, soup):
    # long alphanumeric string in hidden input field or cookie
    # keywords: csrf, nonce, token
    # negative cookie keyword: session

    form_present = False
    if soup.find('form'):
        form_present = True
    csrf_keywords = ['csrf', 'token', 'nonce']
    token_regex = '[a-zA-Z0-9]{20,}'

    for cookie in response_cookies:
        if any(keyword.casefold() in cookie.name.casefold() for keyword in csrf_keywords):
            if not 'session'.casefold() in cookie.name.casefold():
                if re.search(token_regex, cookie.value, re.I):
                    return CsrfResult(csrf_token_found=True, form_present=form_present)

    hidden_inputs = soup.find_all('input', type='hidden')
    for hidden_input in hidden_inputs:
        hidden_input_string = str(hidden_input).casefold()
        if any(keyword.casefold() in hidden_input_string for keyword in csrf_keywords):
            if re.search(token_regex, hidden_input_string, re.I):
                return CsrfResult(csrf_token_found=True, form_present=form_present)

    return CsrfResult(csrf_token_found=False, form_present=form_present)


def analyze_csp(hostname):
    highest_severity_finding = Severity.AllGood
    csp = []
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
        return CspResult(csp_present=False,
                         csp=csp,
                         highest_severity_finding=highest_severity_finding,
                         timeout_on_csp_evaluator=True)
    except UnexpectedAlertPresentException:
        return CspResult(csp_present=False,
                         csp=csp,
                         highest_severity_finding=highest_severity_finding,
                         timeout_on_csp_evaluator=False)
    finally:
        driver.quit()
    if 'data-tooltip="High severity finding"' in evaluated_csp_html:
        highest_severity_finding = Severity.High
    elif 'data-tooltip="Medium severity finding"' in evaluated_csp_html:
        highest_severity_finding = Severity.Medium
    elif 'data-tooltip="Possible high severity finding"' in evaluated_csp_html:
        highest_severity_finding = Severity.PossiblyHigh
    elif 'data-tooltip="Possible medium severity finding"' in evaluated_csp_html:
        highest_severity_finding = Severity.PossiblyMedium

    response = requests.post('https://csp-evaluator.withgoogle.com/getCSP',
                             data={'url': f'https://{hostname}'},
                             timeout=10,
                             headers={'User-Agent': USER_AGENT_CHROME})
    csp = response.json()['csp'].split(';')
    csp = [re.sub(r'\s+', ' ', x) for x in csp]

    return CspResult(csp_present=True,
                     csp=csp,
                     highest_severity_finding=highest_severity_finding,
                     timeout_on_csp_evaluator=False)


def analyze_cors(soup, har_entries):
    for entry in har_entries:
        for request_header in entry['request']['headers']:
            if request_header['name'].casefold() == 'Origin'.casefold():
                if request_header['value'].casefold() != 'None'.casefold():
                    # Origin header is set, so this is either a CORS or a POST request
                    # TODO what do we do with this information?
                    pass
    cross_origin_use_credentials = False
    if soup.find_all(True, crossorigin=re.compile('^use-credentials$', re.I)):
        cross_origin_use_credentials = True
    return CorsResult(cross_origin_use_credentials=cross_origin_use_credentials)


def analyze_cors_policy(response_headers, response_url):
    access_control_allow_origin_header = response_headers.get('Access-Control-Allow-Origin', '')
    x_permitted_cross_domain_policies_header = response_headers.get('X-Permitted-Cross-Domain-Policies')
    x_permitted_cross_domain_policies_set_to_none = False
    lazy_wildcard = False
    crossdomain_xml_present = False
    clientaccesspolicy_xml_present = False
    if access_control_allow_origin_header and access_control_allow_origin_header == '*':
        lazy_wildcard = True
    if not x_permitted_cross_domain_policies_header \
            or x_permitted_cross_domain_policies_header.casefold() == 'none'.casefold():
        x_permitted_cross_domain_policies_set_to_none = True

    hostname = urlparse(response_url).hostname
    crossdomain_xml = requests.get(f'https://{hostname}/crossdomain.xml',
                                   timeout=10,
                                   headers={'User-Agent': USER_AGENT_CHROME})
    clientaccesspolicy_xml = requests.get(f'https://{hostname}/clientaccesspolicy.xml',
                                          timeout=10,
                                          headers={'User-Agent': USER_AGENT_CHROME})

    if crossdomain_xml.status_code == 200:
        crossdomain_xml_present = True
    if clientaccesspolicy_xml.status_code == 200:
        clientaccesspolicy_xml_present = True

    return CorsPolicyResult(access_control_allow_origin_header=access_control_allow_origin_header,
                            lazy_wildcard=lazy_wildcard,
                            x_permitted_cross_domain_policies_set_to_none=x_permitted_cross_domain_policies_set_to_none,
                            crossdomain_xml_present=crossdomain_xml_present,
                            clientaccesspolicy_xml_present=clientaccesspolicy_xml_present)


def analyze_cookie_security(response_cookies, soup):
    cookies_set_via_meta_tags = False
    secure = True
    http_only = True
    same_site = True
    for cookie in response_cookies:
        if not cookie.secure:
            secure = False
        if not cookie.has_nonstandard_attr('HttpOnly'):
            http_only = False
        if not cookie.get_nonstandard_attr('SameSite', default='').casefold() == 'Strict'.casefold():
            same_site = False

    set_cookie_metas = soup.find_all('meta', attrs={"http-equiv": re.compile("^Set-Cookie$", re.I)})
    if set_cookie_metas:
        cookies_set_via_meta_tags = True
    for cookie in set_cookie_metas:
        match = re.search('content="(.*)"', str(cookie), re.I)
        if match:
            content = match.group(1)
            split_content = [x.casefold() for x in content.split(';')]
            if 'Secure'.casefold() not in split_content:
                secure = False
            if 'HttpOnly'.casefold() not in split_content:
                http_only = False
            if 'SameSite=Strict'.casefold() not in split_content:
                same_site = False

    return CookieSecurityResult(secure=secure,
                                http_only=http_only,
                                same_site=same_site,
                                cookies_set_via_meta_tags=cookies_set_via_meta_tags)


def analyze_expect_ct(response_headers):
    expect_ct_header = response_headers.get('Expect-CT')
    enforce_mode = False
    report_mode = False
    misconfigured_max_age = False
    if expect_ct_header is None:
        return ExpectCtResult(expect_ct_header_present=False,
                              misconfigured_max_age=False,
                              enforce_mode=False,
                              report_mode=False)
    if 'enforce'.casefold() in expect_ct_header.casefold().split(','):
        enforce_mode = True
    if 'report-uri="'.casefold() in expect_ct_header.casefold():
        report_mode = True
    if re.search('max-age=(\\d+)', expect_ct_header, flags=re.I) is None:
        misconfigured_max_age = True
    return ExpectCtResult(expect_ct_header_present=True,
                          misconfigured_max_age=misconfigured_max_age,
                          enforce_mode=enforce_mode,
                          report_mode=report_mode)


def analyze_x_download_options(response_headers):
    download_options_header = response_headers.get('X-Download-Options')
    if download_options_header and 'noopen'.casefold() == download_options_header.casefold():
        return XDownloadOptionsResult(noopen=True)
    return XDownloadOptionsResult(noopen=False)


def analyze_x_frame_options(response_headers):
    frame_options_header = response_headers.get('X-Frame-Options')
    if frame_options_header and 'DENY'.casefold() == frame_options_header.casefold():
        return XFrameOptionsResult(deny=True, sameorigin=False)
    if frame_options_header and 'SAMEORIGIN'.casefold() == frame_options_header.casefold():
        return XFrameOptionsResult(deny=False, sameorigin=True)
    return XFrameOptionsResult(deny=False, sameorigin=False)


def analyze_x_xss_protection(response_headers):
    xss_protection_header = response_headers.get('X-XSS-Protection')
    if xss_protection_header and '0' == xss_protection_header[0]:
        return XXssProtectionResult(x_xss_protection_header_present=True, x_xss_protection_disabled=True)
    if xss_protection_header and '1' == xss_protection_header[0]:
        return XXssProtectionResult(x_xss_protection_header_present=True, x_xss_protection_disabled=False)
    return XXssProtectionResult(x_xss_protection_header_present=False, x_xss_protection_disabled=False)


def analyze_x_content_type_options(response_headers):
    content_type_options_header = response_headers.get('X-Content-Type-Options')
    nosniff = False
    if content_type_options_header and 'nosniff'.casefold() == content_type_options_header.casefold():
        nosniff = True
    return XContentTypeOptionsResult(nosniff=nosniff)


def analyze_hpkp(response_headers):
    hpkp_header = response_headers.get('Public-Key-Pins')
    if hpkp_header is None:
        return HpkpResult(hpkp_header_present=False, max_age=0, include_sub_domains=False)
    if 'pin-sha256'.casefold() not in hpkp_header.casefold():
        return HpkpResult(hpkp_header_present=False, max_age=0, include_sub_domains=False)

    max_age_match = re.search('max-age=(\\d+)', hpkp_header, flags=re.I)
    if max_age_match is None:
        return HpkpResult(hpkp_header_present=False, max_age=0, include_sub_domains=False)
    max_age = int(max_age_match.group(1))
    include_sub_domains = False
    if 'includeSubDomains'.casefold() in hpkp_header.casefold():
        include_sub_domains = True
    return HpkpResult(hpkp_header_present=True, max_age=max_age, include_sub_domains=include_sub_domains)


def analyze_hsts(response_headers):
    hsts_header = response_headers.get('Strict-Transport-Security')
    if hsts_header is None:
        return HstsResult(hsts_header_present=False, max_age=0, include_sub_domains=False, preload=False)

    max_age_match = re.search('max-age=(\\d+)', hsts_header, flags=re.I)
    if max_age_match is None:
        HstsResult(hsts_header_present=False, max_age=0, include_sub_domains=False, preload=False)
    max_age = int(max_age_match.group(1))
    include_sub_domains = False
    preload = False
    if 'includeSubDomains'.casefold() in hsts_header.casefold():
        include_sub_domains = True
        if 'preload'.casefold() in hsts_header.casefold():
            preload = True

    return HstsResult(hsts_header_present=True,
                      max_age=max_age,
                      include_sub_domains=include_sub_domains,
                      preload=preload)


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


def analyze_tls(hostname):
    supported_cipher_suites = get_supported_tls_cipher_suites(hostname)
    ssl2_or_ssl3_accepted = False
    weak_tls10_or_tls11_accepted = False
    tls10_or_tls11_accepted = False
    tls_12_or_higher_accepted = False
    if supported_cipher_suites['accepted_ssl2'] or supported_cipher_suites['accepted_ssl3']:
        ssl2_or_ssl3_accepted = True
    if supported_cipher_suites['accepted_tls10'] or supported_cipher_suites['accepted_tls11']:
        tls10_or_tls11_accepted = True
        weak_cipher_keywords = ['NULL', 'MD5', 'RC4', '3DES', 'EXPORT', 'anon']
        for accepted_suites in (supported_cipher_suites['accepted_tls10'] + supported_cipher_suites['accepted_tls11']):
            if not supported_cipher_suites['supports_fallback_scsv'] \
                    or any(x in accepted_suites for x in weak_cipher_keywords):
                weak_tls10_or_tls11_accepted = True
                break
    if supported_cipher_suites['accepted_tls12'] or supported_cipher_suites['accepted_tls13']:
        tls_12_or_higher_accepted = True

    return TlsResult(ssl2_or_ssl3_accepted=ssl2_or_ssl3_accepted,
                     weak_tls10_or_tls11_accepted=weak_tls10_or_tls11_accepted,
                     tls10_or_tls11_accepted=tls10_or_tls11_accepted,
                     tls_12_or_higher_accepted=tls_12_or_higher_accepted)


def analyze_http_redirection(response):
    initial_redirect_to_different_host = False
    redirection_chain_contains_http = False
    if urlparse(response.url).scheme != 'https':
        return HttpRedirectionResult(does_redirect_to_https=False,
                                     initial_redirect_to_different_host=False,
                                     redirection_chain_contains_http=False)
    # (1) Sites should avoid initial redirections to a different host, as this prevents HSTS from being set.
    initial_redirect = response.history[0]
    hostname_request = urlparse(initial_redirect.url).hostname
    hostname_redirect = urlparse(initial_redirect.headers['Location']).hostname
    if hostname_redirect != hostname_request:
        initial_redirect_to_different_host = True

    # (2) In case of multiple redirections (Redirection Chain), every single redirection has to use HTTPS,
    # which prevents the traffic from being intercepted in cleartext.
    for redirect in response.history:
        if urlparse(redirect.headers['Location']).scheme != 'https':
            redirection_chain_contains_http = True
            break
    return HttpRedirectionResult(does_redirect_to_https=True,
                                 initial_redirect_to_different_host=initial_redirect_to_different_host,
                                 redirection_chain_contains_http=redirection_chain_contains_http)


def analyze(site):
    try:
        site = re.sub(r'^https?://', '', site)
        response = requests.get(f'http://{site}', timeout=10, headers={'User-Agent': USER_AGENT_CHROME})
        redirected_hostname = urlparse(response.url).hostname
        redirected_site = re.sub(r'^https?://', '', response.url)
        # phase 0
        http_redirection_result = analyze_http_redirection(response)
        # phase 1
        tls_result = analyze_tls(redirected_hostname)
        # phase 2
        response = requests.get(f'https://{redirected_site}', timeout=10, headers={'User-Agent': USER_AGENT_CHROME})
        response_ie = requests.get(f'https://{redirected_site}', timeout=10, headers={'User-Agent': USER_AGENT_IE})
        response_headers = response.headers
        response_cookies = response.cookies
        response_url = response.url
        soup = BeautifulSoup(response.text, features='html.parser')

        server = Server("browsermob-proxy-2.1.4\\bin\\browsermob-proxy")
        server.start()
        proxy = server.create_proxy()
        options = webdriver.ChromeOptions()
        options.add_argument(f'--proxy-server={proxy.proxy}')
        driver = webdriver.Chrome(options=options)
        proxy.new_har()
        driver.get(f'https://{redirected_site}')
        har_entries = proxy.har['log']['entries']
        with open('libraries.js') as f:
            javascript = f.read()
        third_party_libs = driver.execute_script(javascript)
        proxy.close()
        server.stop()
        driver.quit()

        hsts_result = analyze_hsts(response_headers)
        hpkp_result = analyze_hpkp(response_headers)
        x_content_type_options_result = analyze_x_content_type_options(response_headers)
        x_xss_protection_result = analyze_x_xss_protection(response_headers)
        x_frame_options_result = analyze_x_frame_options(response_headers)
        x_download_options_result = analyze_x_download_options(response_ie.headers)
        expect_ct_result = analyze_expect_ct(response_headers)
        # phase 3
        cookie_security_result = analyze_cookie_security(response_cookies, soup)
        cors_policy_result = analyze_cors_policy(response_headers, response_url)
        csp_result = analyze_csp(redirected_site)
        csrf_result = analyze_csrf(response_cookies, soup)

        cors_result = analyze_cors(soup, har_entries)
        referrer_policy_result = analyze_referrer_policy(response_headers, response_url, soup, har_entries)
        cache_control_result = analyze_cache_control(response_headers, soup)
        leaking_server_software_info_result = analyze_leaking_server_software_info(response_headers)
        # phase 4
        mixed_content_result = analyze_mixed_content(har_entries)
        sri_result = analyze_sri_protection(soup)
        cross_domain_existence_result = analyze_cross_domain_existence(response_url, har_entries)
        third_party_libs_result = analyze_third_party_libs(third_party_libs)

        result = SuccessResult(site=site,
                               timestamp=datetime.datetime.now(),
                               http_redirection_result=http_redirection_result,
                               tls_result=tls_result,
                               hsts_result=hsts_result,
                               hpkp_result=hpkp_result,
                               x_content_type_options_result=x_content_type_options_result,
                               x_xss_protection_result=x_xss_protection_result,
                               x_frame_options_result=x_frame_options_result,
                               x_download_options_result=x_download_options_result,
                               expect_ct_result=expect_ct_result,
                               cookie_security_result=cookie_security_result,
                               cors_policy_result=cors_policy_result,
                               cors_result=cors_result,
                               csp_result=csp_result,
                               csrf_result=csrf_result,
                               referrer_policy_result=referrer_policy_result,
                               cache_control_result=cache_control_result,
                               leaking_server_software_info_result=leaking_server_software_info_result,
                               mixed_content_result=mixed_content_result,
                               sri_result=sri_result,
                               cross_domain_existence_result=cross_domain_existence_result,
                               third_party_libs_result=third_party_libs_result
                               )
    except Exception as e:
        result = ErrorResult(site=site, timestamp=datetime.datetime.now(), error_msg=str(e))
    return result
