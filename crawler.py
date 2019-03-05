import requests
from urllib.parse import urlparse


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


def determine_x_frame_options_score():
    # TODO
    return -1


def determine_x_xss_protection_score():
    # TODO
    return -1


def determine_x_content_type_options_score():
    # TODO
    return -1


def determine_hpkp_score():
    # TODO
    return -1


def determine_hsts_score():
    # TODO
    return -1


def determine_tls_score():
    # TODO
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


def get_response(hostname):
    return requests.get(f'http://{hostname}', timeout=10)


def analyze(hostname):
    response = get_response(hostname)
    # phase 0
    http_redirection_score = determine_http_redirection_score(response)
    # phase 1
    tls_score = determine_tls_score()
    # phase 2
    hsts_score = determine_hsts_score()
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


analyze('google.com')
analyze('github.com')
analyze('vr-bank.de')
analyze('sparkasse.de')
analyze('sparkasse-nuernberg.de')
