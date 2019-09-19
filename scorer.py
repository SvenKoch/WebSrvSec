import pymongo
import results
from bson import ObjectId


class Scorer:
    def __init__(self, result: results.SuccessResult):
        self.result = result

    def up_to_date_third_party_lib_score(self):
        # TODO
        pass

    # return 0 if any cross-domain requests query non-existing domains
    # return 1 otherwise
    def cross_domain_existence_score(self):
        if self.result.cross_domain_existence_result.query_to_non_existing_domain:
            return 0
        return 1

    # return 0 if no cross-origin-resources are integrity-checked
    # return 1 if some cross-origin-resources are integrity-checked
    # return 2 if all cross-origin-resources are integrity-checked
    def sri_score(self):
        # TODO consider require-sri-for CSP policy
        if not self.result.sri_result.unprotected_cors_script_and_link_tags:
            return 2
        if self.result.sri_result.protected_cors_script_and_link_tags:
            return 1
        return 0

    # return 0 if mixed content was detected
    # return 1 otherwise
    def mixed_content_score(self):
        # TODO consider upgrade-insecure-requests CSP policy
        if self.result.mixed_content_result.outgoing_http_request_urls:
            return 0
        return 1

    def cache_control_score(self):
        # TODO
        return -1

    def referrer_policy_score(self):
        # TODO
        referrer_policy_header = self.result.referrer_policy_result.referrer_policy_header
        if referrer_policy_header == 'no-referrer'.casefold():
            pass
        elif referrer_policy_header == 'origin'.casefold():
            pass
        elif referrer_policy_header == 'origin-when-cross-origin'.casefold():
            pass
        elif referrer_policy_header == 'same-origin'.casefold():
            pass
        elif referrer_policy_header == 'strict-origin'.casefold():
            pass
        elif referrer_policy_header == 'strict-origin-when-cross-origin'.casefold():
            pass
        elif referrer_policy_header == 'unsafe-url'.casefold():
            pass
        elif referrer_policy_header == 'no-referrer-when-downgrade'.casefold():
            pass
        else:
            # no-referrer-when-downgrade is default
            pass

        return -1

    # return 0 if no csrf token was found but a form is present
    # return 1 if no csrf token was found but no form was present
    # return 2 if csrf token was found
    def csrf_score(self):
        if self.result.csrf_result.csrf_token_found:
            return 2
        if self.result.csrf_result.form_present:
            return 0
        return 1

    # return -1 on timeout
    # return 0 if no Content Security Policy is found
    # return 1 if evaluation of CSP yields high severity finding(s)
    # return 2 if evaluation of CSP yields medium severity finding(s)
    # return 3 if evaluation of CSP yields possible high severity finding(s)
    # return 4 if evaluation of CSP yields possible medium severity finding(s)
    # return 5 if evaluation of CSP yields no (possibly) negative findings
    def csp_score(self):
        if self.result.csp_result.timeout_on_csp_evaluator:
            return -1
        if not self.result.csp_result.csp_present:
            return 0
        highest_severity_finding = self.result.csp_result.highest_severity_finding
        if highest_severity_finding == results.Severity.High:
            return 1
        if highest_severity_finding == results.Severity.Medium:
            return 2
        if highest_severity_finding == results.Severity.PossiblyHigh:
            return 3
        if highest_severity_finding == results.Severity.PossiblyMedium:
            return 4
        if highest_severity_finding == results.Severity.AllGood:
            return 5

    # return 0 if crossorigin="use-credentials" was found in HTML source
    # return 1 otherwise
    def cors_score(self):
        if self.result.cors_result.cross_origin_use_credentials:
            return 0
        return 1

    # return 0 if Access-Control-Allow-Origin header is set to *
    # return 1 if Access-Control-Allow-Origin header is present
    # return 2 if Access-Control-Allow-Origin header is absent
    # add 3 for X-Permitted-Cross-Domain-Policies: none
    # or if neither crossdomain.xml nor clientaccesspolicy.xml are present
    def cors_policy_score(self):
        if self.result.cors_policy_result.lazy_wildcard:
            score = 0
        elif self.result.cors_policy_result.access_control_allow_origin_header:
            score = 1
        else:
            score = 2

        if self.result.cors_policy_result.x_permitted_cross_domain_policies_set_to_none \
            or (not self.result.cors_policy_result.crossdomain_xml_present
                and not self.result.cors_policy_result.clientaccesspolicy_xml_present):
            score += 3
        return score

    # return 15 if all cookies contain the Secure, HttpOnly and SameSite=Strict directives and are set via header
    # subtract 1 for missing SameSite directive
    # subtract 2 for missing HttpOnly directive
    # subtract 4 for missing Secure directive
    # subtract 8 for cookies set via meta tag in HTML source
    def cookie_security_score(self):
        score = 15
        if self.result.cookie_security_result.cookies_set_via_meta_tags:
            score -= 8
        if not self.result.cookie_security_result.secure:
            score -= 4
        if not self.result.cookie_security_result.http_only:
            score -= 2
        if not self.result.cookie_security_result.same_site:
            score -= 1
        return score

    # return 0 if Expect-CT header is absent or max-age is missing
    # return 1 if in report-only mode
    # return 2 if in enforce(-and-report)-mode
    def expect_ct_score(self):
        if not self.result.expect_ct_result.expect_ct_header_present:
            return 0
        if self.result.expect_ct_result.enforce_mode and not self.result.expect_ct_result.misconfigured_max_age:
            return 2
        if self.result.expect_ct_result.report_mode and not self.result.expect_ct_result.misconfigured_max_age:
            return 1
        return 0

    # return 1 if X-Download-Options: is set to noopen
    # return 0 otherwise
    def x_download_options_score(self):
        if self.result.x_download_options_result.noopen:
            return 1
        return 0

    # return 1 if X-Frame-Options is set to DENY or SAMEORIGIN
    # return 0 otherwise
    def x_frame_options_score(self):
        if self.result.x_frame_options_result.deny or self.result.x_frame_options_result.sameorigin:
            return 1
        return 0

    # return 0 if X-XSS-Protection is set to 0
    # return 1 if X-XSS-Protection header is absent
    # return 2 if X-XSS-Protection is set to 1
    def x_xss_protection_score(self):
        if not self.result.x_xss_protection_result.x_xss_protection_header_present:
            return 1
        if self.result.x_xss_protection_result.x_xss_protection_disabled:
            return 0
        return 2

    # return 1 if X-Content-Type-Options is set to nosniff
    # return 0 otherwise
    def x_content_type_options_score(self):
        if self.result.x_content_type_options_result.nosniff:
            return 1
        return 0

    # return 0 if no valid HPKP response header is present
    # return 1 if HPKP response header is present
    # add 1 if max-age is between 15 and 120 days
    # add 2 for includeSubDomains option
    def hpkp_score(self):
        if not self.result.hpkp_result.hpkp_header_present:
            return 0
        max_age = self.result.hpkp_result.max_age
        if max_age < 15 * 24 * 60 * 60 or max_age > 120 * 24 * 60 * 60:
            score = 1
        else:
            score = 2
        if self.result.hpkp_result.include_sub_domains:
            score += 2
        return score

    # return 0 if no valid HSTS response header is present
    # return 1 if HSTS response header is present but max-age is lower than 120 days
    # return 2 if HSTS response headers is present and max-age is higher than 120 days
    # add 2 for includeSubDomains option
    # add another 2 for preload option (includeSubDomains is mandatory in this case)
    def hsts_score(self):
        if not self.result.hsts_result.hsts_header_present:
            return 0
        if self.result.hsts_result.max_age < 120 * 24 * 60 * 60:
            score = 1
        else:
            score = 2
        if self.result.hsts_result.include_sub_domains:
            score += 2
            if self.result.hsts_result.preload:
                score += 2
        return score

    # return -1 if no accepted cipher suites were identified with any TLS version
    # return 0 if SSL 2.0 or 3.0 cipher suites are supported by the server
    # return 1 if weak TLS 1.0 or 1.1 cipher suites are supported by the server
    # or the server is missing TLS Fallback Signaling Cipher Suite Value support
    # return 2 for TLS 1.0 or 1.1 otherwise
    # return 3 for TLS 1.2+
    def tls_score(self):
        if self.result.tls_result.ssl2_or_ssl3_accepted:
            return 0
        if self.result.tls_result.tls10_or_tls11_accepted:
            if self.result.tls_result.weak_tls10_or_tls11_accepted:
                return 1
            return 2
        if self.result.tls_result.tls_12_or_higher_accepted:
            return 3
        return -1

    # return 0 if site does not redirect to https
    # return 4 for perfect redirection
    # subtract 2 if initial redirect is to different host
    # subtract 1 if redirection chain contains http site
    def http_redirection_score(self):
        if not self.result.http_redirection_result.does_redirect_to_https:
            return 0
        score = 4
        if self.result.http_redirection_result.initial_redirect_to_different_host:
            score -= 2
        if self.result.http_redirection_result.redirection_chain_contains_http:
            score -= 1
        return score

    @classmethod
    def init_from_database(cls, database_name, collection_name, result_id):
        col = pymongo.MongoClient().get_database(name=database_name).get_collection(name=collection_name)
        result = col.find({'_id': ObjectId(result_id)})
        if result is None:
            raise ValueError(f'There is no result with id {result_id}')
        return Scorer(result)
