import datetime
import enum
from dataclasses import dataclass
from typing import List, Dict


@dataclass(frozen=True)
class CrossDomainExistenceResult:
    query_to_non_existing_domain: bool
    non_existing_domains: List[str]


@dataclass(frozen=True)
class SriResult:
    protected_cors_script_and_link_tags: List[str]
    unprotected_cors_script_and_link_tags: List[str]


@dataclass(frozen=True)
class MixedContentResult:
    outgoing_http_request_urls: List[str]


@dataclass(frozen=True)
class LeakingServerSoftwareInfoResult:
    server_header_present: bool
    server_header_contains_version: bool
    x_powered_by_header_present: bool
    x_powered_by_header_contains_version: bool


@dataclass(frozen=True)
class ThirdPartyLibsResult:
    third_party_libs: List[Dict[str, str]]


@dataclass(frozen=True)
class CacheControlResult:
    private_directive: bool
    no_store_directive: bool
    no_cache_directive: bool
    must_revalidate: bool
    max_age_0: bool
    pragma_no_cache: bool


@dataclass(frozen=True)
class ReferrerPolicyResult:
    referrer_policy_header: str
    url_leaked_in_cross_domain_request: bool
    meta_policy: str
    multiple_meta_policies: bool


@dataclass(frozen=True)
class CsrfResult:
    csrf_token_found: bool
    form_present: bool


class Severity(enum.Enum):
    High = 4,
    Medium = 3,
    PossiblyHigh = 2,
    PossiblyMedium = 1,
    AllGood = 0


@dataclass(frozen=True)
class CspResult:
    csp_present: bool
    csp: List[str]
    highest_severity_finding: Severity
    timeout_on_csp_evaluator: bool


@dataclass(frozen=True)
class CorsResult:
    cross_origin_use_credentials: bool


@dataclass(frozen=True)
class CorsPolicyResult:
    access_control_allow_origin_header: str
    lazy_wildcard: bool
    x_permitted_cross_domain_policies_set_to_none: bool
    crossdomain_xml_present: bool
    clientaccesspolicy_xml_present: bool


@dataclass(frozen=True)
class CookieSecurityResult:
    secure: bool
    http_only: bool
    same_site: bool
    cookies_set_via_meta_tags: bool


@dataclass(frozen=True)
class ExpectCtResult:
    expect_ct_header_present: bool
    misconfigured_max_age: bool
    enforce_mode: bool
    report_mode: bool


@dataclass(frozen=True)
class XDownloadOptionsResult:
    noopen: bool


@dataclass(frozen=True)
class XFrameOptionsResult:
    deny: bool
    sameorigin: bool


@dataclass(frozen=True)
class XXssProtectionResult:
    x_xss_protection_header_present: bool
    x_xss_protection_disabled: bool


@dataclass(frozen=True)
class XContentTypeOptionsResult:
    nosniff: bool


@dataclass(frozen=True)
class HpkpResult:
    hpkp_header_present: bool
    max_age: int
    include_sub_domains: bool


@dataclass(frozen=True)
class HstsResult:
    hsts_header_present: bool
    max_age: int
    include_sub_domains: bool
    preload: bool


@dataclass(frozen=True)
class TlsResult:
    ssl2_or_ssl3_accepted: bool
    weak_tls10_or_tls11_accepted: bool
    tls10_or_tls11_accepted: bool
    tls_12_or_higher_accepted: bool


@dataclass(frozen=True)
class HttpRedirectionResult:
    does_redirect_to_https: bool
    initial_redirect_to_different_host: bool
    redirection_chain_contains_http: bool


@dataclass(frozen=True)
class Result:
    site: str
    timestamp: datetime.datetime


@dataclass(frozen=True)
class SuccessResult(Result):
    cross_domain_existence_result: CrossDomainExistenceResult
    sri_result: SriResult
    mixed_content_result: MixedContentResult
    leaking_server_software_info_result: LeakingServerSoftwareInfoResult
    third_party_libs_result: ThirdPartyLibsResult
    cache_control_result: CacheControlResult
    referrer_policy_result: ReferrerPolicyResult
    csrf_result: CsrfResult
    csp_result: CspResult
    cors_result: CorsResult
    cors_policy_result: CorsPolicyResult
    cookie_security_result: CookieSecurityResult
    expect_ct_result: ExpectCtResult
    x_download_options_result: XDownloadOptionsResult
    x_frame_options_result: XFrameOptionsResult
    x_xss_protection_result: XXssProtectionResult
    x_content_type_options_result: XContentTypeOptionsResult
    hpkp_result: HpkpResult
    hsts_result: HstsResult
    tls_result: TlsResult
    http_redirection_result: HttpRedirectionResult


@dataclass(frozen=True)
class ErrorResult(Result):
    error_msg: str
