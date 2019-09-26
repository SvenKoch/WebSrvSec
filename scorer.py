import pymongo
import results
from bson import ObjectId


class Scorer:
    def __init__(self, result: results.SuccessResult):
        self.result = result

    def up_to_date_server_software_score(self):
        # TODO
        return -1

    def up_to_date_third_party_lib_score(self):
        # TODO
        return -1

    # return 0 if any cross-domain requests query non-existing domains
    # return 100 otherwise
    def cross_domain_existence_score(self):
        if self.result.cross_domain_existence_result.query_to_non_existing_domain:
            return 0
        return 100

    # return 0 if no cross-origin-resources are integrity-checked
    # return 20 if some cross-origin-resources are integrity-checked
    # return 90 if all cross-origin-resources are integrity-checked
    # add 10 for require-sri-for script CSP policy
    def sri_score(self):
        if not self.result.sri_result.unprotected_cors_script_and_link_tags:
            for directive in self.result.csp_result.csp:
                if directive.casefold().startswith('require-sri-for '):
                    return 100
            return 90
        if self.result.sri_result.protected_cors_script_and_link_tags:
            return 20
        return 0

    # return 0 if mixed content was detected
    # return 90 otherwise
    # add 10 for upgrade-insecure-requests CSP policy
    def mixed_content_score(self):
        if self.result.mixed_content_result.outgoing_http_request_urls:
            return 0
        if 'upgrade-insecure-requests' in self.result.csp_result.csp:
            return 100
        return 90

    # return 100 for Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0 and Pragma: no-cache
    # subtract 50 for missing private directive
    # subtract 50 for missing no-store directive
    # subtract 10 for every other missing directive
    def cache_control_score(self):
        score = 100
        if not self.result.cache_control_result.private_directive:
            score -= 50
        if not self.result.cache_control_result.no_store_directive:
            score -= 50
        if not self.result.cache_control_result.no_cache_directive:
            score -= 10
        if not self.result.cache_control_result.must_revalidate:
            score -= 10
        if not self.result.cache_control_result.max_age_0:
            score -= 10
        if not self.result.cache_control_result.pragma_no_cache:
            score -= 10
        return max(0, score)

    # return 0 for unsafe-url policy
    # return 10 if origin is also leaked to HTTP connections
    # return 100 for no-referrer or same-origin policy
    # return 20 otherwise
    def referrer_policy_score(self):
        referrer_policy_header = self.result.referrer_policy_result.referrer_policy_header
        if referrer_policy_header == 'no-referrer'.casefold():
            return 100
        elif referrer_policy_header == 'origin'.casefold():
            return 10
        elif referrer_policy_header == 'origin-when-cross-origin'.casefold():
            return 10
        elif referrer_policy_header == 'same-origin'.casefold():
            return 100
        elif referrer_policy_header == 'strict-origin'.casefold():
            return 20
        elif referrer_policy_header == 'strict-origin-when-cross-origin'.casefold():
            return 20
        elif referrer_policy_header == 'unsafe-url'.casefold():
            return 0
        elif referrer_policy_header == 'no-referrer-when-downgrade'.casefold():
            return 20

        meta_policy = self.result.referrer_policy_result.meta_policy
        if meta_policy and not self.result.referrer_policy_result.multiple_meta_policies:
            if meta_policy == 'no-referrer'.casefold():
                return 100
            elif meta_policy == 'origin'.casefold():
                return 10
            elif meta_policy == 'origin-when-cross-origin'.casefold():
                return 10
            elif meta_policy == 'same-origin'.casefold():
                return 100
            elif meta_policy == 'strict-origin'.casefold():
                return 20
            elif meta_policy == 'strict-origin-when-cross-origin'.casefold():
                return 20
            elif meta_policy == 'unsafe-url'.casefold():
                return 0
            elif meta_policy == 'no-referrer-when-downgrade'.casefold():
                return 20
        # no-referrer-when-downgrade is default
        return 20

    # return 0 if no csrf token was found but a form is present
    # return 90 if no csrf token was found but no form was present
    #   or if csrf token was found
    def csrf_score(self):
        if self.result.csrf_result.csrf_token_found:
            return 100
        if self.result.csrf_result.form_present:
            return 0
        return 90

    # return -1 on timeout
    # return 0 if no Content Security Policy is found
    # return 10 if evaluation of CSP yields high severity finding(s)
    # return 20 if evaluation of CSP yields medium severity finding(s)
    # return 40 if evaluation of CSP yields possible high severity finding(s)
    # return 50 if evaluation of CSP yields possible medium severity finding(s)
    # return 100 if evaluation of CSP yields no (possibly) negative findings
    def csp_score(self):
        if self.result.csp_result.timeout_on_csp_evaluator:
            return -1
        if not self.result.csp_result.csp_present:
            return 0
        highest_severity_finding = self.result.csp_result.highest_severity_finding
        if highest_severity_finding == results.Severity.High:
            return 10
        if highest_severity_finding == results.Severity.Medium:
            return 20
        if highest_severity_finding == results.Severity.PossiblyHigh:
            return 40
        if highest_severity_finding == results.Severity.PossiblyMedium:
            return 50
        if highest_severity_finding == results.Severity.AllGood:
            return 100

    # return 0 if crossorigin="use-credentials" was found in HTML source
    # return 100 otherwise
    def cors_score(self):
        if self.result.cors_result.cross_origin_use_credentials:
            return 0
        return 100

    # return 0 if Access-Control-Allow-Origin header is set to *
    # return 20 if Access-Control-Allow-Origin header is present
    # return 80 if Access-Control-Allow-Origin header is absent
    # add 20 for X-Permitted-Cross-Domain-Policies: none
    # or if neither crossdomain.xml nor clientaccesspolicy.xml are present
    def cors_policy_score(self):
        if self.result.cors_policy_result.lazy_wildcard:
            score = 0
        elif self.result.cors_policy_result.access_control_allow_origin_header:
            score = 20
        else:
            score = 80

        if self.result.cors_policy_result.x_permitted_cross_domain_policies_set_to_none \
                or (not self.result.cors_policy_result.crossdomain_xml_present
                    and not self.result.cors_policy_result.clientaccesspolicy_xml_present):
            score += 20
        return score

    # return 100 if all cookies contain the Secure, HttpOnly and SameSite=Strict directives and are set via header
    # subtract 10 for missing SameSite directive
    # subtract 60 for missing HttpOnly directive
    # subtract 60 for missing Secure directive
    # subtract 20 for cookies set via meta tag in HTML source
    def cookie_security_score(self):
        score = 100
        if self.result.cookie_security_result.cookies_set_via_meta_tags:
            score -= 20
        if not self.result.cookie_security_result.secure:
            score -= 60
        if not self.result.cookie_security_result.http_only:
            score -= 60
        if not self.result.cookie_security_result.same_site:
            score -= 10
        return max(0, score)

    # return 0 if Expect-CT header is absent or max-age is missing
    # return 60 if in report-only mode
    # return 100 if in enforce(-and-report)-mode
    def expect_ct_score(self):
        if not self.result.expect_ct_result.expect_ct_header_present:
            return 0
        if self.result.expect_ct_result.enforce_mode and not self.result.expect_ct_result.misconfigured_max_age:
            return 100
        if self.result.expect_ct_result.report_mode and not self.result.expect_ct_result.misconfigured_max_age:
            return 60
        return 0

    # return 100 if X-Download-Options: is set to noopen
    # return 0 otherwise
    def x_download_options_score(self):
        if self.result.x_download_options_result.noopen:
            return 100
        return 0

    # return 100 if X-Frame-Options is set to DENY or SAMEORIGIN
    # return 0 otherwise
    def x_frame_options_score(self):
        if self.result.x_frame_options_result.deny or self.result.x_frame_options_result.sameorigin:
            return 100
        return 0

    # return 0 if X-XSS-Protection is set to 0
    # return 80 if X-XSS-Protection header is absent or set
    # return 100 if X-XSS-Protection is set to 1
    def x_xss_protection_score(self):
        if not self.result.x_xss_protection_result.x_xss_protection_header_present:
            return 80
        if self.result.x_xss_protection_result.x_xss_protection_disabled:
            return 0
        return 100

    # return 100 if X-Content-Type-Options is set to nosniff
    # return 0 otherwise
    def x_content_type_options_score(self):
        if self.result.x_content_type_options_result.nosniff:
            return 100
        return 0

    # return 0 if no valid HPKP response header is present
    # return 60 if HPKP response header is present
    # add 20 if max-age is between 15 and 120 days
    # add 20 for includeSubDomains option
    def hpkp_score(self):
        if not self.result.hpkp_result.hpkp_header_present:
            return 0
        max_age = self.result.hpkp_result.max_age
        if max_age < 15 * 24 * 60 * 60 or max_age > 120 * 24 * 60 * 60:
            score = 60
        else:
            score = 80
        if self.result.hpkp_result.include_sub_domains:
            score += 20
        return score

    # return 0 if no valid HSTS response header is present
    # return 40 if HSTS response header is present but max-age is lower than 120 days
    # return 60 if HSTS response headers is present and max-age is higher than 120 days
    # add 20 for includeSubDomains option
    # add another 20 for preload option (includeSubDomains is mandatory in this case)
    def hsts_score(self):
        if not self.result.hsts_result.hsts_header_present:
            return 0
        if self.result.hsts_result.max_age < 120 * 24 * 60 * 60:
            score = 40
        else:
            score = 60
        if self.result.hsts_result.include_sub_domains:
            score += 20
            if self.result.hsts_result.preload:
                score += 20
        return score

    # return 0 if
    #   - no accepted cipher suites were identified with any TLS version
    #   - SSL 2.0 or 3.0 cipher suites are supported by the server
    # return 20 if weak TLS 1.0 or 1.1 cipher suites are supported by the server
    #       or the server is missing TLS Fallback Signaling Cipher Suite Value support
    # return 80 for TLS 1.0 or 1.1 otherwise
    # return 100 for TLS 1.2+
    def tls_score(self):
        if self.result.tls_result.ssl2_or_ssl3_accepted:
            return 0
        if self.result.tls_result.tls10_or_tls11_accepted:
            if self.result.tls_result.weak_tls10_or_tls11_accepted:
                return 20
            return 80
        if self.result.tls_result.tls_12_or_higher_accepted:
            return 100
        return 0

    # return 0 if site does not redirect to https
    # return 100 for perfect redirection
    # subtract 20 if initial redirect is to different host
    # subtract 40 if redirection chain contains http site
    def http_redirection_score(self):
        if not self.result.http_redirection_result.does_redirect_to_https:
            return 0
        score = 100
        if self.result.http_redirection_result.initial_redirect_to_different_host:
            score -= 20
        if self.result.http_redirection_result.redirection_chain_contains_http:
            score -= 40
        return score

    def total_score(self):
        if self.http_redirection_score() == 0 or self.tls_score() == 0:
            return 0
        mandatory_weights = {
            'cross_domain_existence': 5,
            'sri': 1,
            'mixed_content': 1,
            'up_to_date_server_software': 0,
            'up_to_date_third_party_lib': 0,
            'cache_control': 1,
            'referrer_policy': 1,
            'csp': 1,
            'cors': 1,
            'cors_policy': 1,
            'cookie_security': 1,
            'x_download_options': 0.5,
            'x_frame_options': 1,
            'x_xss_protection': 1,
            'x_content_type_options': 1,
            'hsts': 1,
            'tls': 5,
            'http_redirection': 5
        }
        if self.result.csp_result.timeout_on_csp_evaluator:
            mandatory_weights['csp'] = 0
        bonus_weights = {
            'csrf': 1,
            'expect_ct': 1,
            'hpkp': 1,
        }
        score = self.http_redirection_score() * mandatory_weights['http_redirection'] \
                + self.tls_score() * mandatory_weights['tls'] \
                + self.hsts_score() * mandatory_weights['hsts'] \
                + self.x_content_type_options_score() * mandatory_weights['x_content_type_options'] \
                + self.x_xss_protection_score() * mandatory_weights['x_xss_protection'] \
                + self.x_frame_options_score() * mandatory_weights['x_frame_options'] \
                + self.x_download_options_score() * mandatory_weights['x_download_options'] \
                + self.cookie_security_score() * mandatory_weights['cookie_security'] \
                + self.cors_policy_score() * mandatory_weights['cors_policy'] \
                + self.csp_score() * mandatory_weights['csp'] \
                + self.referrer_policy_score() * mandatory_weights['referrer_policy'] \
                + self.cache_control_score() * mandatory_weights['cache_control'] \
                + self.up_to_date_third_party_lib_score() * mandatory_weights['up_to_date_third_party_lib'] \
                + self.up_to_date_server_software_score() * mandatory_weights['up_to_date_server_software'] \
                + self.mixed_content_score() * mandatory_weights['mixed_content'] \
                + self.sri_score() * mandatory_weights['sri'] \
                + self.cross_domain_existence_score() * mandatory_weights['cross_domain_existence']
        sum_weights = sum(mandatory_weights.values())
        avg_score = score / sum_weights
        if self.hpkp_score() > avg_score:
            score += self.hpkp_score() * bonus_weights['hpkp']
            sum_weights += bonus_weights['hpkp']
            avg_score = score / sum_weights
        if self.expect_ct_score() > avg_score:
            score += self.expect_ct_score() * bonus_weights['expect_ct']
            sum_weights += bonus_weights['expect_ct']
            avg_score = score / sum_weights
        if self.csrf_score() > avg_score:
            score += self.csrf_score() * bonus_weights['csrf']
            sum_weights += bonus_weights['csrf']
            avg_score = score / sum_weights

        if self.tls_score() <= 20:
            return min(self.tls_score(), int(avg_score))
        return int(avg_score)

    @classmethod
    def init_from_database(cls, database_name, collection_name, result_id):
        col = pymongo.MongoClient().get_database(name=database_name).get_collection(name=collection_name)
        result = col.find({'_id': ObjectId(result_id)})
        if result is None:
            raise ValueError(f'There is no result with id {result_id}')
        return Scorer(result)
