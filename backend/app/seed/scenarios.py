"""The planted story: scenarios S1 to S7 and their ground truth.

Every value here is hand-authored so the expected outcomes in the PRD actually
occur when the deterministic scoring in `mcp_server.scoring` and the greedy
solver in `mcp_server.solver` run over the generated graph.

Shape of the day-1 attack-path set this produces (13 paths):

    gateway      -> auth-svc -> payments-api -> payments-vault   5 hops  S2, top score
    web-bff      -> orders-api -> ledger-pg                      4 hops  S3 family
    mobile-bff   -> catalog-svc -> customers-pg                  4 hops  S3 family
    support-bff  -> ticket-svc -> customers-pg                   4 hops  S3 family
    docs-api     -> archive-svc -> archive-s3                    4 hops  S3 family
    partner-api  -> profile-svc -> identity-pg                   4 hops  S3 family (oidc)
    admin-bff    -> config-svc -> secrets-kv                     4 hops  S3 family (basic)
    status-api   -> audit-svc -> ledger-pg                       4 hops  S3 family
    checkout-web -> checkout-api -> role -> payments-vault        5 hops  S3 family
    invoice-api  -> billing-svc -> ledger-pg                     4 hops  residual, one control
    notify-api   -> ticket-svc -> customers-pg                   4 hops  residual
    upload-svc   -> archive-svc -> archive-s3                    4 hops  residual

`internal-http-client@2.1.0` is the single live exploit behind nine of those
paths across eight public entry points, which is why the greedy solver picks
upgrading it first even though its effort cost is the highest.
"""

from __future__ import annotations

from typing import Any

SCAN_DAY1 = "scan-2026-10-14"
SCAN_DAY2 = "scan-2026-10-15"

SYNTHETIC_NOTE = (
    "Synthetic estate. Public CVE identifiers carry approximate real severity; identifiers "
    "beginning ACME- are invented for invented internal packages."
)

# --- vulnerabilities ---------------------------------------------------------
# (id, cvss, epss, kev, attack_vector, requires_auth, fixed_in, summary)
PLANTED_VULNERABILITIES: list[dict[str, Any]] = [
    {
        "id": "CVE-2021-44228",
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "epss": 0.975,
        "kev": True,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "2.17.1",
        "summary": "Log4Shell: JNDI lookup in message formatting allows remote code execution.",
    },
    {
        "id": "CVE-2022-22965",
        "cve": "CVE-2022-22965",
        "cvss": 9.8,
        "epss": 0.972,
        "kev": True,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "5.3.18",
        "summary": "Spring4Shell: data binding on JDK 9+ allows remote code execution.",
    },
    {
        "id": "CVE-2022-42889",
        "cve": "CVE-2022-42889",
        "cvss": 9.8,
        "epss": 0.941,
        "kev": True,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.10.0",
        "summary": "Text4Shell: script interpolation in Commons Text allows remote code execution.",
    },
    {
        "id": "CVE-2021-44906",
        "cve": "CVE-2021-44906",
        "cvss": 9.8,
        "epss": 0.021,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.2.6",
        "summary": "Prototype pollution in minimist allows arbitrary property injection.",
    },
    {
        "id": "CVE-2022-23529",
        "cve": "CVE-2022-23529",
        "cvss": 7.6,
        "epss": 0.009,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": True,
        "fixed_in": "9.0.0",
        "summary": "jsonwebtoken verify() can execute attacker-controlled code with an untrusted key.",
    },
    {
        "id": "CVE-2022-0235",
        "cve": "CVE-2022-0235",
        "cvss": 6.1,
        "epss": 0.047,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "2.6.7",
        "summary": "node-fetch leaks cookies and the Authorization header across cross-site redirects.",
    },
    {
        "id": "CVE-2023-44487",
        "cve": "CVE-2023-44487",
        "cvss": 7.5,
        "epss": 0.894,
        "kev": True,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.58.0",
        "summary": "HTTP/2 rapid reset enables a request-flood denial of service.",
    },
    {
        "id": "CVE-2023-24998",
        "cve": "CVE-2023-24998",
        "cvss": 7.5,
        "epss": 0.083,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.5",
        "summary": "Commons FileUpload does not limit the number of request parts.",
    },
    {
        "id": "CVE-2024-21538",
        "cve": "CVE-2024-21538",
        "cvss": 7.5,
        "epss": 0.004,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "7.0.5",
        "summary": "Regular expression denial of service in cross-spawn.",
    },
    {
        "id": "CVE-2023-26159",
        "cve": "CVE-2023-26159",
        "cvss": 7.5,
        "epss": 0.012,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.15.4",
        "summary": "Improper URL parsing in follow-redirects discloses the Authorization header.",
    },
    {
        "id": "CVE-2022-25883",
        "cve": "CVE-2022-25883",
        "cvss": 5.3,
        "epss": 0.004,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "7.5.2",
        "summary": "Regular expression denial of service in the semver range parser.",
    },
    {
        "id": "CVE-2020-8203",
        "cve": "CVE-2020-8203",
        "cvss": 7.4,
        "epss": 0.006,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "4.17.19",
        "summary": "Prototype pollution in lodash zipObjectDeep.",
    },
    {
        "id": "ACME-2024-0002",
        "cve": "ACME-2024-0002",
        "cvss": 5.3,
        "epss": 0.42,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "2.4.0",
        "summary": (
            "session-sdk writes the raw session identifier into debug responses, letting an "
            "unauthenticated caller recover a valid session."
        ),
    },
    {
        "id": "ACME-2024-0003",
        "cve": "ACME-2024-0003",
        "cvss": 6.1,
        "epss": 0.50,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.5.0",
        "summary": (
            "auth-core trusts a client-supplied subject header, so a caller that reaches it can act "
            "as any principal."
        ),
    },
    {
        "id": "ACME-2023-0007",
        "cve": "ACME-2023-0007",
        "cvss": 7.5,
        "epss": 0.21,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "2.3.0",
        "summary": (
            "internal-http-client follows redirects to arbitrary hosts and replays the caller's "
            "service token."
        ),
    },
    {
        "id": "ACME-2023-0008",
        "cve": "ACME-2023-0008",
        "cvss": 6.8,
        "epss": 0.14,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "2.3.0",
        "summary": "internal-http-client caches responses across tenants when Vary is absent.",
    },
    {
        "id": "ACME-2024-0005",
        "cve": "ACME-2024-0005",
        "cvss": 8.8,
        "epss": 0.11,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "1.0.0",
        "summary": "notebook-proxy exposes an unauthenticated kernel execution endpoint.",
    },
    {
        "id": "ACME-2024-0009",
        "cve": "ACME-2024-0009",
        "cvss": 7.5,
        "epss": 0.33,
        "kev": False,
        "attack_vector": "network",
        "requires_auth": False,
        "fixed_in": "3.2.0",
        "summary": (
            "query-dsl builds store filters by string concatenation, allowing filter injection on "
            "the backing store."
        ),
    },
]

# --- packages ----------------------------------------------------------------
# (name, version, ecosystem, internal)
PLANTED_PACKAGES: list[dict[str, Any]] = [
    {"name": "session-sdk", "version": "2.3.0", "ecosystem": "npm", "internal": True},
    {"name": "auth-core", "version": "1.4.2", "ecosystem": "maven", "internal": True},
    {"name": "internal-http-client", "version": "2.1.0", "ecosystem": "maven", "internal": True},
    {"name": "notebook-proxy", "version": "0.9.1", "ecosystem": "pypi", "internal": True},
    {"name": "query-dsl", "version": "3.1.0", "ecosystem": "go", "internal": True},
    {"name": "log4j-core", "version": "2.14.1", "ecosystem": "maven", "internal": False},
    {"name": "spring-beans", "version": "5.3.15", "ecosystem": "maven", "internal": False},
    {"name": "commons-text", "version": "1.9", "ecosystem": "maven", "internal": False},
    {"name": "commons-fileupload", "version": "1.4", "ecosystem": "maven", "internal": False},
    {"name": "jackson-databind", "version": "2.13.0", "ecosystem": "maven", "internal": False},
    {"name": "okhttp", "version": "4.9.1", "ecosystem": "maven", "internal": False},
    {"name": "minimist", "version": "1.2.5", "ecosystem": "npm", "internal": False},
    {"name": "node-fetch", "version": "2.6.6", "ecosystem": "npm", "internal": False},
    {"name": "jsonwebtoken", "version": "8.5.1", "ecosystem": "npm", "internal": False},
    {"name": "lodash", "version": "4.17.15", "ecosystem": "npm", "internal": False},
    {"name": "cross-spawn", "version": "7.0.3", "ecosystem": "npm", "internal": False},
    {"name": "follow-redirects", "version": "1.15.1", "ecosystem": "npm", "internal": False},
    {"name": "semver", "version": "7.3.5", "ecosystem": "npm", "internal": False},
    {"name": "grpc-js", "version": "1.57.0", "ecosystem": "npm", "internal": False},
]

# Filler packages carry filler vulnerabilities; the generator spreads them.
FILLER_PACKAGE_NAMES: list[tuple[str, str, str]] = [
    ("express", "4.17.1", "npm"),
    ("axios", "0.21.1", "npm"),
    ("tar", "6.1.0", "npm"),
    ("moment", "2.29.1", "npm"),
    ("ws", "7.4.6", "npm"),
    ("ejs", "3.1.6", "npm"),
    ("qs", "6.9.4", "npm"),
    ("netty-codec", "4.1.68", "maven"),
    ("snakeyaml", "1.29", "maven"),
    ("guava", "30.1-jre", "maven"),
    ("httpclient", "4.5.12", "maven"),
    ("bcprov-jdk15on", "1.68", "maven"),
    ("protobuf-java", "3.16.1", "maven"),
    ("tomcat-embed-core", "9.0.45", "maven"),
    ("requests", "2.25.1", "pypi"),
    ("urllib3", "1.26.4", "pypi"),
    ("pyyaml", "5.3.1", "pypi"),
    ("django", "3.2.4", "pypi"),
    ("jinja2", "2.11.3", "pypi"),
    ("pillow", "8.2.0", "pypi"),
    ("gorilla-mux", "1.8.0", "go"),
    ("go-jose", "2.5.1", "go"),
    ("yaml-v3", "3.0.0", "go"),
    ("grpc-go", "1.40.0", "go"),
    ("body-parser", "1.19.0", "npm"),
    ("cookie-parser", "1.4.5", "npm"),
    ("jsdom", "16.4.0", "npm"),
    ("handlebars", "4.7.6", "npm"),
    ("mustache", "4.0.1", "npm"),
    ("socket-io", "3.1.1", "npm"),
    ("mongoose", "5.11.15", "npm"),
    ("pg-promise", "10.9.1", "npm"),
    ("ioredis", "4.19.4", "npm"),
    ("node-sass", "5.0.0", "npm"),
    ("undici", "4.16.0", "npm"),
    ("fast-xml-parser", "3.17.4", "npm"),
    ("sharp", "0.27.0", "npm"),
    ("archiver", "5.2.0", "npm"),
    ("nodemailer", "6.4.17", "npm"),
    ("spring-web", "5.3.15", "maven"),
    ("spring-security-core", "5.4.2", "maven"),
    ("hibernate-core", "5.4.27", "maven"),
    ("logback-classic", "1.2.3", "maven"),
    ("jetty-server", "9.4.35", "maven"),
    ("xstream", "1.4.15", "maven"),
    ("groovy", "3.0.7", "maven"),
    ("commons-io", "2.8.0", "maven"),
    ("commons-compress", "1.20", "maven"),
    ("httpcore", "4.4.13", "maven"),
    ("postgresql-jdbc", "42.2.18", "maven"),
    ("kafka-clients", "2.7.0", "maven"),
    ("jsoup", "1.13.1", "maven"),
    ("woodstox-core", "6.2.3", "maven"),
    ("h2", "1.4.200", "maven"),
    ("flask", "1.1.2", "pypi"),
    ("werkzeug", "1.0.1", "pypi"),
    ("sqlalchemy", "1.3.22", "pypi"),
    ("celery", "5.0.5", "pypi"),
    ("boto-core", "1.19.52", "pypi"),
    ("cryptography", "3.3.1", "pypi"),
    ("lxml", "4.6.2", "pypi"),
    ("numpy", "1.19.5", "pypi"),
    ("pandas", "1.2.0", "pypi"),
    ("aiohttp", "3.7.3", "pypi"),
    ("paramiko", "2.7.2", "pypi"),
    ("psycopg2", "2.8.6", "pypi"),
    ("redis-py", "3.5.3", "pypi"),
    ("markdown2", "2.3.10", "pypi"),
    ("go-redis", "8.4.0", "go"),
    ("go-chi", "4.1.2", "go"),
    ("zap", "1.16.0", "go"),
    ("viper", "1.7.1", "go"),
    ("prometheus-client-golang", "1.9.0", "go"),
    ("aws-sdk-go", "1.36.29", "go"),
    ("jwt-go", "3.2.0", "go"),
    ("pgx", "4.10.1", "go"),
    ("cobra", "1.1.1", "go"),
    ("testify", "1.6.1", "go"),
]

INTERNAL_FILLER_PACKAGE_NAMES: list[tuple[str, str, str]] = [
    ("acme-telemetry", "4.2.0", "maven"),
    ("acme-config-client", "1.9.3", "maven"),
    ("acme-feature-flags", "0.8.2", "npm"),
    ("acme-ui-kit", "6.1.0", "npm"),
    ("acme-schema", "2.0.4", "pypi"),
    ("acme-retry", "1.1.1", "go"),
    ("acme-authz", "3.3.0", "maven"),
    ("acme-tracing", "2.7.5", "go"),
]

# --- data stores -------------------------------------------------------------
DATA_STORES: list[dict[str, Any]] = [
    {"id": "payments-vault", "name": "payments-vault", "kind": "vault", "classification": "pci", "records": 4_200_000, "crown_jewel": True},
    {"id": "customers-pg", "name": "customers-pg", "kind": "postgres", "classification": "pii", "records": 8_400_000, "crown_jewel": True},
    {"id": "ledger-pg", "name": "ledger-pg", "kind": "postgres", "classification": "pci", "records": 2_100_000, "crown_jewel": True},
    {"id": "identity-pg", "name": "identity-pg", "kind": "postgres", "classification": "pii", "records": 12_000_000, "crown_jewel": True},
    {"id": "archive-s3", "name": "archive-s3", "kind": "s3", "classification": "pii", "records": 90_000_000, "crown_jewel": True},
    {"id": "secrets-kv", "name": "secrets-kv", "kind": "vault", "classification": "secrets", "records": 48_000, "crown_jewel": True},
    {"id": "cache-redis", "name": "cache-redis", "kind": "redis", "classification": "internal", "records": 0, "crown_jewel": False},
    {"id": "events-kafka", "name": "events-kafka", "kind": "kafka", "classification": "internal", "records": 1_200_000, "crown_jewel": False},
    {"id": "metrics-pg", "name": "metrics-pg", "kind": "postgres", "classification": "internal", "records": 54_000_000, "crown_jewel": False},
    {"id": "public-assets-s3", "name": "public-assets-s3", "kind": "s3", "classification": "public", "records": 310_000, "crown_jewel": False},
    {"id": "staging-pg", "name": "staging-pg", "kind": "postgres", "classification": "internal", "records": 120_000, "crown_jewel": False},
    {"id": "sandbox-s3", "name": "sandbox-s3", "kind": "s3", "classification": "internal", "records": 2_400_000, "crown_jewel": False},
]

# --- teams -------------------------------------------------------------------
TEAMS: list[dict[str, Any]] = [
    {"id": "team-edge", "name": "Edge Platform", "slack_channel": "#edge-platform"},
    {"id": "team-identity", "name": "Identity", "slack_channel": "#identity"},
    {"id": "team-payments", "name": "Payments", "slack_channel": "#payments-oncall"},
    {"id": "team-commerce", "name": "Commerce", "slack_channel": "#commerce"},
    {"id": "team-support", "name": "Support Tooling", "slack_channel": "#support-tools"},
    {"id": "team-platform", "name": "Platform", "slack_channel": "#platform-eng"},
    {"id": "team-data", "name": "Data Platform", "slack_channel": "#data-platform"},
    {"id": "team-ml", "name": "ML Research", "slack_channel": "#ml-research"},
    {"id": "team-logistics", "name": "Logistics", "slack_channel": "#logistics"},
]

PERSON_NAMES: list[tuple[str, str]] = [
    ("Ada Kowalski", "sre"),
    ("Bram de Vries", "backend"),
    ("Chiara Rossi", "appsec"),
    ("Dmitri Volkov", "backend"),
    ("Esi Mensah", "sre"),
    ("Farah Haddad", "appsec"),
    ("Gunnar Olsen", "backend"),
    ("Hana Suzuki", "platform"),
    ("Idris Bello", "backend"),
    ("Jana Novak", "sre"),
    ("Kiran Nair", "backend"),
    ("Lea Fischer", "appsec"),
    ("Mateo Alvarez", "backend"),
    ("Nour Khalil", "platform"),
    ("Oskar Lindqvist", "sre"),
    ("Priya Raman", "backend"),
    ("Quentin Blanc", "platform"),
    ("Rosa Ferreira", "backend"),
    ("Sami Virtanen", "sre"),
    ("Tomas Horak", "backend"),
    ("Ulrike Braun", "appsec"),
    ("Viktor Petrov", "backend"),
    ("Wanjiru Kamau", "platform"),
    ("Xiulan Chen", "backend"),
    ("Yusuf Demir", "sre"),
    ("Zaneta Wisniewska", "backend"),
    ("Arjun Gupta", "platform"),
    ("Bianca Moretti", "appsec"),
    ("Caleb Mwangi", "backend"),
    ("Dalia Haddadin", "sre"),
    ("Emil Johansson", "backend"),
    ("Fatou Diallo", "platform"),
    ("Goran Markovic", "backend"),
    ("Hilde Bakker", "appsec"),
    ("Ines Carvalho", "sre"),
]

# --- services ----------------------------------------------------------------
# status defaults to 'active', env to 'prod'
PLANTED_SERVICES: list[dict[str, Any]] = [
    {"id": "gateway", "name": "gateway", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-edge"},
    {"id": "auth-svc", "name": "auth-svc", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-identity"},
    {"id": "payments-api", "name": "payments-api", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "web-bff", "name": "web-bff", "language": "typescript", "tier": 1, "cluster": "prod-eu", "team": "team-edge"},
    {"id": "mobile-bff", "name": "mobile-bff", "language": "typescript", "tier": 1, "cluster": "prod-eu", "team": "team-edge"},
    {"id": "support-bff", "name": "support-bff", "language": "typescript", "tier": 2, "cluster": "prod-us", "team": "team-support"},
    {"id": "docs-api", "name": "docs-api", "language": "go", "tier": 2, "cluster": "prod-us", "team": "team-data"},
    {"id": "partner-api", "name": "partner-api", "language": "java", "tier": 2, "cluster": "prod-eu", "team": "team-logistics"},
    {"id": "admin-bff", "name": "admin-bff", "language": "typescript", "tier": 2, "cluster": "prod-eu", "team": "team-platform"},
    {"id": "status-api", "name": "status-api", "language": "go", "tier": 3, "cluster": "prod-us", "team": "team-edge"},
    {"id": "checkout-web", "name": "checkout-web", "language": "typescript", "tier": 1, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "orders-api", "name": "orders-api", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "catalog-svc", "name": "catalog-svc", "language": "go", "tier": 2, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "ticket-svc", "name": "ticket-svc", "language": "python", "tier": 2, "cluster": "prod-us", "team": "team-support"},
    {"id": "archive-svc", "name": "archive-svc", "language": "python", "tier": 3, "cluster": "prod-us", "team": "team-data"},
    {"id": "profile-svc", "name": "profile-svc", "language": "go", "tier": 2, "cluster": "prod-eu", "team": "team-identity"},
    {"id": "config-svc", "name": "config-svc", "language": "go", "tier": 2, "cluster": "prod-eu", "team": "team-platform"},
    {"id": "audit-svc", "name": "audit-svc", "language": "java", "tier": 2, "cluster": "prod-us", "team": "team-platform"},
    {"id": "checkout-api", "name": "checkout-api", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "billing-svc", "name": "billing-svc", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "invoice-api", "name": "invoice-api", "language": "python", "tier": 2, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "notify-api", "name": "notify-api", "language": "typescript", "tier": 3, "cluster": "prod-us", "team": "team-support"},
    {"id": "upload-svc", "name": "upload-svc", "language": "go", "tier": 3, "cluster": "prod-us", "team": "team-platform"},
    {"id": "edge-gw", "name": "edge-gw", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-edge"},
    {"id": "report-renderer", "name": "report-renderer", "language": "java", "tier": 3, "cluster": "prod-eu", "team": "team-data"},
    {"id": "legacy-export", "name": "legacy-export", "language": "java", "tier": 3, "cluster": "prod-eu", "team": "team-data", "status": "decommissioned"},
    {"id": "ml-notebooks", "name": "ml-notebooks", "language": "python", "tier": 3, "cluster": "sandbox-eu", "team": "team-ml", "env": "sandbox"},
    {"id": "feature-lab", "name": "feature-lab", "language": "python", "tier": 3, "cluster": "sandbox-eu", "team": "team-ml", "env": "sandbox"},
    {"id": "search-api", "name": "search-api", "language": "go", "tier": 2, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "identity-svc", "name": "identity-svc", "language": "java", "tier": 1, "cluster": "prod-eu", "team": "team-identity"},
    {"id": "shipping-api", "name": "shipping-api", "language": "go", "tier": 2, "cluster": "prod-us", "team": "team-logistics"},
    {"id": "inventory-api", "name": "inventory-api", "language": "java", "tier": 2, "cluster": "prod-us", "team": "team-commerce"},
    {"id": "pricing-svc", "name": "pricing-svc", "language": "java", "tier": 2, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "notify-svc", "name": "notify-svc", "language": "typescript", "tier": 3, "cluster": "prod-us", "team": "team-support"},
    {"id": "cart-api", "name": "cart-api", "language": "typescript", "tier": 2, "cluster": "prod-eu", "team": "team-commerce"},
]

FILLER_SERVICES: list[dict[str, Any]] = [
    {"id": "metrics-collector", "language": "go", "tier": 3, "cluster": "prod-us", "team": "team-platform"},
    {"id": "feature-flags", "language": "typescript", "tier": 3, "cluster": "staging-eu", "team": "team-platform", "env": "staging"},
    {"id": "tax-svc", "language": "java", "tier": 2, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "geo-svc", "language": "go", "tier": 3, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "email-svc", "language": "python", "tier": 3, "cluster": "prod-us", "team": "team-support"},
    {"id": "pdf-svc", "language": "python", "tier": 3, "cluster": "prod-us", "team": "team-data"},
    {"id": "warehouse-sync", "language": "java", "tier": 3, "cluster": "prod-us", "team": "team-logistics"},
    {"id": "fraud-scoring", "language": "python", "tier": 2, "cluster": "prod-eu", "team": "team-payments"},
    {"id": "loyalty-api", "language": "typescript", "tier": 3, "cluster": "prod-eu", "team": "team-commerce"},
    {"id": "chat-relay", "language": "typescript", "tier": 3, "cluster": "staging-eu", "team": "team-support", "env": "staging"},
]

# --- ingress -----------------------------------------------------------------
INGRESS: list[dict[str, Any]] = [
    {"id": "ing-www", "host": "www.acme.example", "public": True, "waf": True, "authn": "none", "service": "web-bff", "path_prefix": "/"},
    {"id": "ing-session", "host": "session.acme.example", "public": True, "waf": False, "authn": "none", "service": "gateway", "path_prefix": "/session"},
    {"id": "ing-edge", "host": "api.acme.example", "public": True, "waf": True, "authn": "oidc", "service": "edge-gw", "path_prefix": "/api"},
    {"id": "ing-mobile", "host": "m.acme.example", "public": True, "waf": True, "authn": "none", "service": "mobile-bff", "path_prefix": "/m"},
    {"id": "ing-support", "host": "help.acme.example", "public": True, "waf": False, "authn": "none", "service": "support-bff", "path_prefix": "/help"},
    {"id": "ing-docs", "host": "docs.acme.example", "public": True, "waf": False, "authn": "none", "service": "docs-api", "path_prefix": "/docs"},
    {"id": "ing-partner", "host": "partners.acme.example", "public": True, "waf": True, "authn": "oidc", "service": "partner-api", "path_prefix": "/partner"},
    {"id": "ing-admin", "host": "admin.acme.example", "public": True, "waf": True, "authn": "basic", "service": "admin-bff", "path_prefix": "/admin"},
    {"id": "ing-status", "host": "status.acme.example", "public": True, "waf": False, "authn": "none", "service": "status-api", "path_prefix": "/status"},
    {"id": "ing-shop", "host": "shop.acme.example", "public": True, "waf": True, "authn": "none", "service": "checkout-web", "path_prefix": "/shop"},
    {"id": "ing-invoice", "host": "invoices.acme.example", "public": True, "waf": False, "authn": "none", "service": "invoice-api", "path_prefix": "/invoices"},
    {"id": "ing-notify", "host": "hooks.acme.example", "public": True, "waf": False, "authn": "none", "service": "notify-api", "path_prefix": "/hooks"},
    {"id": "ing-upload", "host": "upload.acme.example", "public": True, "waf": False, "authn": "none", "service": "upload-svc", "path_prefix": "/upload"},
    {"id": "ing-lab", "host": "lab-eu.acme.example", "public": True, "waf": False, "authn": "basic", "service": "ml-notebooks", "path_prefix": "/lab"},
    {"id": "ing-internal", "host": "internal.acme.example", "public": False, "waf": False, "authn": "oidc", "service": "identity-svc", "path_prefix": "/identity"},
]

# --- call edges --------------------------------------------------------------
# (src, dst, authz, protocol, rps). authz 'mtls' blocks lateral movement.
PLANTED_CALLS: list[tuple[str, str, str, str, int]] = [
    ("gateway", "auth-svc", "none", "http", 420),
    ("gateway", "catalog-svc", "mtls", "http", 900),
    ("gateway", "identity-svc", "mtls", "grpc", 300),
    ("auth-svc", "payments-api", "jwt", "grpc", 120),
    ("auth-svc", "identity-svc", "mtls", "grpc", 200),
    ("payments-api", "billing-svc", "mtls", "grpc", 60),
    ("web-bff", "orders-api", "jwt", "http", 640),
    ("web-bff", "catalog-svc", "mtls", "http", 820),
    ("web-bff", "pricing-svc", "mtls", "http", 410),
    ("mobile-bff", "catalog-svc", "jwt", "http", 510),
    ("mobile-bff", "orders-api", "mtls", "http", 300),
    ("support-bff", "ticket-svc", "none", "http", 90),
    ("support-bff", "profile-svc", "mtls", "http", 70),
    ("docs-api", "archive-svc", "none", "http", 40),
    ("partner-api", "profile-svc", "none", "http", 55),
    ("partner-api", "catalog-svc", "mtls", "http", 120),
    ("admin-bff", "config-svc", "none", "http", 25),
    ("admin-bff", "inventory-api", "mtls", "http", 45),
    ("status-api", "audit-svc", "none", "http", 30),
    ("checkout-web", "checkout-api", "jwt", "http", 380),
    ("checkout-web", "cart-api", "mtls", "http", 450),
    ("orders-api", "shipping-api", "mtls", "grpc", 210),
    ("orders-api", "checkout-api", "mtls", "grpc", 160),
    ("catalog-svc", "search-api", "mtls", "http", 700),
    ("checkout-api", "payments-api", "mtls", "grpc", 140),
    ("invoice-api", "billing-svc", "none", "http", 35),
    ("notify-api", "ticket-svc", "none", "http", 20),
    ("upload-svc", "archive-svc", "none", "http", 18),
    ("ticket-svc", "notify-svc", "mtls", "http", 15),
    ("profile-svc", "identity-svc", "mtls", "grpc", 95),
    ("config-svc", "audit-svc", "mtls", "http", 12),
    ("audit-svc", "archive-svc", "mtls", "http", 22),
    ("cart-api", "pricing-svc", "mtls", "http", 260),
    ("edge-gw", "gateway", "mtls", "http", 1200),
    ("edge-gw", "catalog-svc", "mtls", "http", 980),
    ("search-api", "catalog-svc", "none", "http", 640),
    ("ml-notebooks", "feature-lab", "none", "http", 5),
    ("inventory-api", "catalog-svc", "mtls", "http", 150),
    ("shipping-api", "notify-svc", "mtls", "http", 40),
    ("pricing-svc", "catalog-svc", "mtls", "http", 180),
    ("identity-svc", "audit-svc", "mtls", "http", 60),
    ("billing-svc", "audit-svc", "mtls", "http", 50),
]

# Filler services are wired with mTLS only, so they never carry an attack path.
FILLER_CALLS: list[tuple[str, str, str, str, int]] = [
    ("metrics-collector", "audit-svc", "mtls", "http", 70),
    ("feature-flags", "config-svc", "mtls", "http", 30),
    ("tax-svc", "pricing-svc", "mtls", "grpc", 110),
    ("geo-svc", "catalog-svc", "mtls", "http", 85),
    ("email-svc", "notify-svc", "mtls", "http", 45),
    ("pdf-svc", "archive-svc", "mtls", "http", 25),
    ("warehouse-sync", "inventory-api", "mtls", "grpc", 55),
    ("fraud-scoring", "payments-api", "mtls", "grpc", 95),
    ("loyalty-api", "orders-api", "mtls", "http", 65),
    ("chat-relay", "ticket-svc", "mtls", "http", 20),
    ("metrics-collector", "feature-flags", "mtls", "http", 15),
    ("geo-svc", "tax-svc", "mtls", "http", 18),
    ("fraud-scoring", "geo-svc", "mtls", "http", 22),
    ("loyalty-api", "email-svc", "mtls", "http", 12),
]

# --- data access -------------------------------------------------------------
# (service, rel, store)
STORE_ACCESS: list[tuple[str, str, str]] = [
    ("payments-api", "WRITES_TO", "payments-vault"),
    ("payments-api", "READS_FROM", "metrics-pg"),
    ("orders-api", "WRITES_TO", "ledger-pg"),
    ("orders-api", "READS_FROM", "cache-redis"),
    ("catalog-svc", "READS_FROM", "customers-pg"),
    ("catalog-svc", "READS_FROM", "cache-redis"),
    ("ticket-svc", "READS_FROM", "customers-pg"),
    ("archive-svc", "WRITES_TO", "archive-s3"),
    ("profile-svc", "READS_FROM", "identity-pg"),
    ("config-svc", "READS_FROM", "secrets-kv"),
    ("audit-svc", "READS_FROM", "ledger-pg"),
    ("audit-svc", "WRITES_TO", "events-kafka"),
    ("billing-svc", "WRITES_TO", "ledger-pg"),
    ("billing-svc", "READS_FROM", "metrics-pg"),
    ("identity-svc", "READS_FROM", "identity-pg"),
    ("identity-svc", "WRITES_TO", "identity-pg"),
    ("report-renderer", "READS_FROM", "archive-s3"),
    ("legacy-export", "READS_FROM", "archive-s3"),
    ("ml-notebooks", "READS_FROM", "sandbox-s3"),
    ("feature-lab", "READS_FROM", "sandbox-s3"),
    ("feature-lab", "WRITES_TO", "sandbox-s3"),
    ("search-api", "READS_FROM", "cache-redis"),
    ("inventory-api", "READS_FROM", "metrics-pg"),
    ("shipping-api", "WRITES_TO", "events-kafka"),
    ("notify-svc", "WRITES_TO", "events-kafka"),
    ("cart-api", "READS_FROM", "cache-redis"),
    ("pricing-svc", "READS_FROM", "metrics-pg"),
    ("checkout-api", "READS_FROM", "cache-redis"),
    ("upload-svc", "READS_FROM", "public-assets-s3"),
    ("docs-api", "READS_FROM", "public-assets-s3"),
    ("status-api", "READS_FROM", "metrics-pg"),
    ("gateway", "READS_FROM", "cache-redis"),
    ("auth-svc", "READS_FROM", "cache-redis"),
    ("web-bff", "READS_FROM", "cache-redis"),
]

FILLER_STORE_ACCESS: list[tuple[str, str, str]] = [
    ("metrics-collector", "WRITES_TO", "metrics-pg"),
    ("feature-flags", "READS_FROM", "staging-pg"),
    ("tax-svc", "READS_FROM", "metrics-pg"),
    ("geo-svc", "READS_FROM", "cache-redis"),
    ("email-svc", "WRITES_TO", "events-kafka"),
    ("pdf-svc", "WRITES_TO", "public-assets-s3"),
    ("warehouse-sync", "READS_FROM", "metrics-pg"),
    ("fraud-scoring", "READS_FROM", "metrics-pg"),
    ("loyalty-api", "READS_FROM", "cache-redis"),
    ("chat-relay", "READS_FROM", "staging-pg"),
]

# --- IAM roles ---------------------------------------------------------------
IAM_ROLES: list[dict[str, Any]] = [
    {"id": "role-payments-writer", "name": "payments-writer", "privilege": "write", "service": "payments-api", "stores": ["payments-vault"]},
    {"id": "role-checkout-writer", "name": "checkout-writer", "privilege": "write", "service": "checkout-api", "stores": ["payments-vault"]},
    {"id": "role-config-reader", "name": "config-reader", "privilege": "read", "service": "config-svc", "stores": ["secrets-kv"]},
    {"id": "role-report-reader", "name": "report-reader", "privilege": "read", "service": "report-renderer", "stores": ["archive-s3"]},
    {"id": "role-legacy-admin", "name": "legacy-admin", "privilege": "admin", "service": "legacy-export", "stores": ["customers-pg", "archive-s3"]},
    {"id": "role-orders-writer", "name": "orders-writer", "privilege": "write", "service": "orders-api", "stores": ["ledger-pg"]},
    {"id": "role-catalog-reader", "name": "catalog-reader", "privilege": "read", "service": "catalog-svc", "stores": ["customers-pg"]},
    {"id": "role-archive-writer", "name": "archive-writer", "privilege": "write", "service": "archive-svc", "stores": ["archive-s3"]},
    {"id": "role-lab-reader", "name": "lab-reader", "privilege": "read", "service": "ml-notebooks", "stores": ["sandbox-s3"]},
    {"id": "role-metrics-writer", "name": "metrics-writer", "privilege": "write", "service": "metrics-collector", "stores": ["metrics-pg"]},
]

# --- controls ----------------------------------------------------------------
CONTROLS: list[dict[str, Any]] = [
    {
        "id": "ctl-vp-edge",
        "name": "edge-gw jndi virtual patch",
        "type": "virtual_patch",
        "active": True,
        "target": "edge-gw",
        "against": "CVE-2021-44228",
    },
    {
        "id": "ctl-waf-edge",
        "name": "api.acme.example rapid-reset rule",
        "type": "waf_rule",
        "active": True,
        "target": "ing-edge",
        "against": "CVE-2023-44487",
    },
    {
        "id": "ctl-np-billing",
        "name": "billing-svc egress policy",
        "type": "network_policy",
        "active": True,
        "target": "billing-svc",
        "against": "CVE-2022-23529",
    },
    {
        "id": "ctl-mtls-identity",
        "name": "identity-svc mutual TLS",
        "type": "mtls",
        "active": True,
        "target": "identity-svc",
        "against": "*",
    },
    {
        "id": "ctl-mtls-pricing",
        "name": "pricing-svc mutual TLS",
        "type": "mtls",
        "active": True,
        "target": "pricing-svc",
        "against": "*",
    },
    {
        "id": "ctl-authz-legacy",
        "name": "legacy-export authz middleware",
        "type": "authz_middleware",
        "active": False,
        "target": "legacy-export",
        "against": "*",
    },
    {
        "id": "ctl-vp-report",
        "name": "report-renderer jndi virtual patch",
        "type": "virtual_patch",
        "active": False,
        "target": "report-renderer",
        "against": "CVE-2021-44228",
    },
    {
        "id": "ctl-np-sandbox",
        "name": "sandbox-eu ingress policy",
        "type": "network_policy",
        "active": True,
        "target": "feature-lab",
        "against": "CVE-2023-44487",
    },
]

# --- package use -------------------------------------------------------------
IHC_SERVICES: list[str] = [
    "web-bff",
    "mobile-bff",
    "support-bff",
    "docs-api",
    "partner-api",
    "admin-bff",
    "status-api",
    "checkout-web",
    "catalog-svc",
    "orders-api",
    "checkout-api",
]

# (package name, package version, [service ids], direct)
PLANTED_DEPENDENCIES: list[tuple[str, str, list[str], bool]] = [
    ("session-sdk", "2.3.0", ["gateway"], True),
    ("auth-core", "1.4.2", ["auth-svc"], True),
    ("internal-http-client", "2.1.0", IHC_SERVICES, True),
    ("log4j-core", "2.14.1", ["report-renderer", "edge-gw"], True),
    ("spring-beans", "5.3.15", ["legacy-export", "identity-svc"], True),
    ("commons-text", "1.9", ["legacy-export", "pricing-svc"], True),
    ("commons-fileupload", "1.4", ["upload-svc"], True),
    ("minimist", "1.2.5", ["invoice-api"], True),
    ("node-fetch", "2.6.6", ["notify-api"], True),
    ("jsonwebtoken", "8.5.1", ["gateway"], True),
    ("lodash", "4.17.15", ["web-bff"], True),
    ("cross-spawn", "7.0.3", ["catalog-svc"], True),
    ("follow-redirects", "1.15.1", ["payments-api"], True),
    ("semver", "7.3.5", ["orders-api"], True),
    ("grpc-js", "1.57.0", ["search-api"], True),
    ("notebook-proxy", "0.9.1", ["ml-notebooks", "feature-lab"], True),
    ("query-dsl", "3.1.0", ["search-api"], True),
    ("jackson-databind", "2.13.0", ["payments-api", "billing-svc"], False),
    ("okhttp", "4.9.1", ["catalog-svc", "orders-api"], False),
]

# (parent package, child package) transitive edges
PACKAGE_DEPENDENCIES: list[tuple[str, str]] = [
    ("internal-http-client", "okhttp"),
    ("session-sdk", "node-fetch"),
    ("auth-core", "jackson-databind"),
    ("query-dsl", "grpc-js"),
]

# --- planted findings --------------------------------------------------------
# (id, service, cve, package name, status, reachable_code)
PLANTED_FINDINGS: list[dict[str, Any]] = [
    {"id": "F-0001", "service": "gateway", "cve": "ACME-2024-0002", "package": "session-sdk", "status": "open", "reachable_code": True},
    {"id": "F-0002", "service": "auth-svc", "cve": "ACME-2024-0003", "package": "auth-core", "status": "open", "reachable_code": True},
    {"id": "F-0003", "service": "report-renderer", "cve": "CVE-2021-44228", "package": "log4j-core", "status": "open", "reachable_code": True},
    {"id": "F-0004", "service": "edge-gw", "cve": "CVE-2021-44228", "package": "log4j-core", "status": "open", "reachable_code": True},
    {"id": "F-0005", "service": "legacy-export", "cve": "CVE-2022-22965", "package": "spring-beans", "status": "open", "reachable_code": True},
    {"id": "F-0006", "service": "legacy-export", "cve": "CVE-2022-42889", "package": "commons-text", "status": "open", "reachable_code": True},
    {"id": "F-0007", "service": "ml-notebooks", "cve": "ACME-2024-0005", "package": "notebook-proxy", "status": "open", "reachable_code": True},
    {"id": "F-0008", "service": "web-bff", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0009", "service": "mobile-bff", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0010", "service": "support-bff", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0011", "service": "docs-api", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0012", "service": "partner-api", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0013", "service": "admin-bff", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0014", "service": "status-api", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0015", "service": "checkout-web", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0016", "service": "catalog-svc", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0017", "service": "orders-api", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": False},
    {"id": "F-0018", "service": "checkout-api", "cve": "ACME-2023-0007", "package": "internal-http-client", "status": "open", "reachable_code": False},
    {"id": "F-0019", "service": "web-bff", "cve": "ACME-2023-0008", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0020", "service": "mobile-bff", "cve": "ACME-2023-0008", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0021", "service": "catalog-svc", "cve": "ACME-2023-0008", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0022", "service": "docs-api", "cve": "ACME-2023-0008", "package": "internal-http-client", "status": "open", "reachable_code": True},
    {"id": "F-0023", "service": "invoice-api", "cve": "CVE-2021-44906", "package": "minimist", "status": "open", "reachable_code": True},
    {"id": "F-0024", "service": "notify-api", "cve": "CVE-2022-0235", "package": "node-fetch", "status": "open", "reachable_code": True},
    {"id": "F-0025", "service": "upload-svc", "cve": "CVE-2023-24998", "package": "commons-fileupload", "status": "open", "reachable_code": True},
    {"id": "F-0026", "service": "gateway", "cve": "CVE-2022-23529", "package": "jsonwebtoken", "status": "open", "reachable_code": False},
    {"id": "F-0027", "service": "web-bff", "cve": "CVE-2020-8203", "package": "lodash", "status": "open", "reachable_code": False},
    {"id": "F-0028", "service": "payments-api", "cve": "CVE-2023-26159", "package": "follow-redirects", "status": "open", "reachable_code": False},
    {"id": "F-0029", "service": "catalog-svc", "cve": "CVE-2024-21538", "package": "cross-spawn", "status": "accepted", "reachable_code": True},
    {"id": "F-0030", "service": "search-api", "cve": "CVE-2023-44487", "package": "grpc-js", "status": "open", "reachable_code": False},
    {"id": "F-0031", "service": "identity-svc", "cve": "CVE-2022-22965", "package": "spring-beans", "status": "open", "reachable_code": True},
    {"id": "F-0032", "service": "pricing-svc", "cve": "CVE-2022-42889", "package": "commons-text", "status": "open", "reachable_code": True},
    {"id": "F-0033", "service": "orders-api", "cve": "CVE-2022-25883", "package": "semver", "status": "open", "reachable_code": False},
]

# --- day-2 delta (S7 and the S6 follow-up) ----------------------------------
DELTA_INGRESS: dict[str, Any] = {
    "id": "ing-search",
    "host": "search.acme.example",
    "public": True,
    "waf": False,
    "authn": "none",
    "service": "search-api",
    "path_prefix": "/search",
}

DELTA_FINDINGS: list[dict[str, Any]] = [
    {"id": "F-0101", "service": "search-api", "cve": "ACME-2024-0009", "package": "query-dsl", "status": "open", "reachable_code": True},
    {"id": "F-0102", "service": "feature-lab", "cve": "ACME-2024-0005", "package": "notebook-proxy", "status": "open", "reachable_code": True},
]

# --- ground truth (never written into the graph) ----------------------------
EXPLOITABLE_FINDINGS: list[str] = [
    "F-0001",
    "F-0002",
    "F-0008",
    "F-0009",
    "F-0010",
    "F-0011",
    "F-0012",
    "F-0013",
    "F-0014",
    "F-0015",
    "F-0016",
    "F-0019",
    "F-0020",
    "F-0021",
    "F-0022",
    "F-0023",
    "F-0024",
    "F-0025",
    "F-0101",
]

PLANTED_DECOYS: list[str] = ["F-0003", "F-0004", "F-0005", "F-0006", "F-0007", "F-0031", "F-0032"]

EXPECTED_VERDICTS: dict[str, str] = {
    "F-0001": "FIX_NOW",
    "F-0002": "FIX_NOW",
    "F-0003": "SUPPRESS",
    "F-0004": "SCHEDULE",
    "F-0005": "SUPPRESS",
    "F-0006": "SUPPRESS",
    "F-0007": "SCHEDULE",
    "F-0008": "FIX_NOW",
    "F-0009": "FIX_NOW",
    "F-0010": "FIX_NOW",
    "F-0011": "FIX_NOW",
    "F-0012": "FIX_NOW",
    "F-0013": "FIX_NOW",
    "F-0014": "FIX_NOW",
    "F-0015": "FIX_NOW",
    "F-0016": "FIX_NOW",
    "F-0017": "SCHEDULE",
    "F-0018": "SCHEDULE",
    "F-0019": "FIX_NOW",
    "F-0020": "FIX_NOW",
    "F-0021": "FIX_NOW",
    "F-0022": "FIX_NOW",
    "F-0023": "FIX_NOW",
    "F-0024": "SCHEDULE",
    "F-0025": "FIX_NOW",
    "F-0026": "SCHEDULE",
    "F-0027": "ACCEPT",
    "F-0028": "SCHEDULE",
    "F-0029": "ACCEPT",
    "F-0030": "SCHEDULE",
    "F-0031": "SCHEDULE",
    "F-0032": "SCHEDULE",
    "F-0033": "ACCEPT",
    "F-0101": "FIX_NOW",
    "F-0102": "ACCEPT",
}

CHOKEPOINT_FIXES: list[str] = ["internal-http-client@2.1.0"]

SCENARIO_NOTES: dict[str, str] = {
    "S1": "F-0003: CVSS 10.0 Log4Shell on report-renderer, a batch job with no ingress route and no inbound calls.",
    "S2": "F-0001 and F-0002: a CVSS 5.3 session leak opens a five-hop route from session.acme.example to payments-vault.",
    "S3": "internal-http-client@2.1.0 is the live exploit behind nine of thirteen paths across eight public entry points.",
    "S4": "F-0004: the same Log4Shell on edge-gw is neutralised by an active virtual patch.",
    "S5": "F-0005 and F-0006: legacy-export is decommissioned, so its admin role to customers-pg is unreachable.",
    "S6": "F-0007: ml-notebooks is in cluster sandbox-eu, which has no call or role route to any production store.",
    "S7": "F-0101: the day-2 scan publishes search.acme.example and adds an injection bug on search-api.",
}


def ground_truth(all_findings: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build the ground-truth document.

    When the full finding table is supplied, every finding at CVSS 8.0 or above
    that is not in the exploitable set is also labelled a decoy, so the
    "decoys in top 10" metric covers generated findings too.
    """
    decoys = list(PLANTED_DECOYS)
    if all_findings:
        exploitable = set(EXPLOITABLE_FINDINGS)
        for finding_id, row in sorted(all_findings.items()):
            if finding_id in exploitable or finding_id in decoys:
                continue
            if float(row.get("cvss") or 0.0) >= 8.0:
                decoys.append(finding_id)
    return {
        "exploitable_findings": list(EXPLOITABLE_FINDINGS),
        "decoys": decoys,
        "chokepoint_fixes": list(CHOKEPOINT_FIXES),
        "expected_verdicts": dict(EXPECTED_VERDICTS),
        "scenarios": dict(SCENARIO_NOTES),
        "note": SYNTHETIC_NOTE,
    }
