import re
from urllib.parse import urlparse

import requests
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, \
    Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError


def save_results(results):
    # TODO
    print(results)


def determine_up_to_date_third_party_lib_score():
    # TODO
    return -1


def determine_js_inclusion_cross_domain_existence_score():
    # TODO
    return -1


def determine_sri_score():
    # TODO
    return -1


def determine_mixed_content_score():
    # TODO
    return -1


def determine_up_to_date_server_software_score():
    # TODO
    return -1


def determine_cache_control_score():
    # TODO
    return -1


def determine_referrer_policy_score():
    # TODO
    return -1


def determine_csrf_score():
    # TODO
    return -1


def determine_csp_score():
    # TODO
    return -1


def determine_cors_score():
    # TODO
    return -1


def determine_cookie_security_score():
    # TODO
    return -1


def determine_expect_ct_score():
    # TODO
    return -1


def determine_x_download_options_score():
    # TODO
    return -1


# return 1 if X-Frame-Options is set to DENY or SAMEORIGIN
# return 0 otherwise
def determine_x_frame_options_score(response_header):
    frame_options_header = response_header['X-Frame-Options']
    if frame_options_header is None:
        return 0
    if 'DENY'.casefold() == frame_options_header.casefold() \
            or 'SAMEORIGIN'.casefold() == frame_options_header.casefold():
        return 1
    else:
        return 0


# return 0 if X-XSS-Protection is set to 0
# return 1 if X-XSS-Protection is absence
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
        server_info = server_tester.perform(network_timeout=5)
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
    response = requests.get(f'http://{hostname}', timeout=10)
    # TODO handle timeout
    redirected_hostname = urlparse(response.url).hostname
    # phase 0
    http_redirection_score = determine_http_redirection_score(response)
    # phase 1
    tls_score = determine_tls_score(redirected_hostname)
    # phase 2
    response = requests.get(f'https://{redirected_hostname}', timeout=10)
    response_headers = response.headers
    hsts_score = determine_hsts_score(response_headers)
    hpkp_score = determine_hpkp_score()
    x_content_type_options_score = determine_x_content_type_options_score()
    x_xss_protection_score = determine_x_xss_protection_score()
    x_frame_options_score = determine_x_frame_options_score()
    x_download_options_score = determine_x_download_options_score()
    expect_ct_score = determine_expect_ct_score()
    # phase 3
    cookie_security_score = determine_cookie_security_score()
    cors_score = determine_cors_score()
    csp_score = determine_csp_score()
    csrf_score = determine_csrf_score()
    referrer_policy_score = determine_referrer_policy_score()
    cache_control_score = determine_cache_control_score()
    up_to_date_server_software_score = determine_up_to_date_server_software_score()
    # phase 4
    mixed_content_score = determine_mixed_content_score()
    sri_score = determine_sri_score()
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
