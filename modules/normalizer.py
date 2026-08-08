"""Converts raw CPE match / version-range data into human-readable strings.

Example: cpe:2.3:a:apache:tomcat:9.0.94 + versionEndExcluding=9.0.95
      -> AffectedProduct(vendor="Apache", product="Tomcat",
                          affected_range="9.0.0 - 9.0.94", fixed_version="9.0.95")
"""
from __future__ import annotations

import logging
import re

from modules.models import AffectedProduct

logger = logging.getLogger("vuln_intel.normalizer")

_SENTINEL_VERSIONS = {"0", "*", "-", "n/a", ""}
_MAX_FIXED_VERSIONS_SHOWN = 3


def _version_sort_key(version: str) -> tuple:
    """Natural sort key so '7.2.10' sorts after '7.2.9' (not before, as plain
    string comparison would). Mixed digit/non-digit chunks compare safely
    because the leading tag (0=numeric, 1=text) keeps types from colliding."""
    chunks = re.split(r"[.\-+]", version)
    return tuple((0, int(c)) if c.isdigit() else (1, c) for c in chunks)


def _parse_cpe(criteria: str) -> tuple[str | None, str | None, str | None]:
    """cpe:2.3:a:vendor:product:version:... -> (vendor, product, version)"""
    parts = criteria.split(":")
    if len(parts) < 6:
        return None, None, None
    vendor, product, version = parts[3], parts[4], parts[5]
    return vendor or None, product or None, (version if version not in ("*", "-") else None)


def normalize_cpe_matches(cpe_matches: list[dict]) -> list[AffectedProduct]:
    """Turn NVD `cpeMatch` entries into readable AffectedProduct rows.

    Handles four NVD range fields (versionStart/EndIncluding/Excluding) plus
    the bare-version case where a CPE pins an exact vulnerable version.
    """
    products: list[AffectedProduct] = []
    seen: set[tuple] = set()

    for match in cpe_matches:
        criteria = match.get("criteria")
        if not criteria or not match.get("vulnerable", True):
            continue
        vendor, product, pinned_version = _parse_cpe(criteria)
        if not vendor or not product:
            continue

        start_inc = match.get("versionStartIncluding")
        start_exc = match.get("versionStartExcluding")
        end_inc = match.get("versionEndIncluding")
        end_exc = match.get("versionEndExcluding")

        fixed_version = end_exc  # first non-vulnerable version == the fix
        upper = end_inc or end_exc
        if start_inc or start_exc:
            lower = start_inc or start_exc
            lower_prefix = ">=" if start_inc else ">"
            if upper:
                upper_prefix = "<=" if end_inc else "<"
                affected_range = f"{lower_prefix} {lower}, {upper_prefix} {upper}"
            else:
                affected_range = f"{lower_prefix} {lower}"
        elif upper:
            affected_range = f"<= {upper}" if end_inc else f"< {upper}"
        elif pinned_version:
            affected_range = pinned_version
        else:
            affected_range = "all versions"

        key = (vendor, product, affected_range, fixed_version)
        if key in seen:
            continue
        seen.add(key)
        products.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                affected_range=affected_range,
                fixed_version=fixed_version,
                status="affected",
            )
        )

    return products


def display_vendor(vendor_raw: str) -> str:
    return CANONICAL_VENDORS.get(vendor_raw.lower(), vendor_raw.replace("_", " ").title())


def display_product(product_raw: str) -> str:
    return product_raw.replace("_", " ").title()


CANONICAL_VENDORS = {
    "microsoft": "Microsoft",
    "cisco": "Cisco",
    "apache": "Apache",
    "vmware": "VMware",
    "fortinet": "Fortinet",
    "google": "Google",
    "oracle": "Oracle",
    "linux": "Linux",
    "redhat": "Red Hat",
    "red_hat": "Red Hat",
    "canonical": "Ubuntu (Canonical)",
    "ubuntu": "Ubuntu",
    "adobe": "Adobe",
    "ibm": "IBM",
    "sap": "SAP",
    "juniper": "Juniper Networks",
    "paloaltonetworks": "Palo Alto Networks",
    "citrix": "Citrix",
    "atlassian": "Atlassian",
    "wordpress": "WordPress",
    "openssl": "OpenSSL",
}


def _normalize_key(s: str) -> str:
    s = re.sub(r"\s*\([^)]*\)\s*$", "", s)  # strip trailing "(Fmc)"-style abbreviations
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _extract_version_tokens(affected_range: str) -> list[str]:
    """Pull bound version tokens out of a range string like '7.2.0 - 7.2.11'
    or '< 9.0.95' so they can be pooled and re-sorted across many rows.

    Splits only on a *whitespace-padded* hyphen (our own range separator,
    always built as f"{lower} - {upper}"), never a bare hyphen — version
    strings like "13.1-62.23" (Citrix/NetScaler build numbers) use hyphens
    internally and must not be torn apart.
    """
    tokens = re.split(r"\s+-\s+|>=|<=|>|<", affected_range)
    return [t.strip() for t in tokens if t.strip() and t.strip().lower() not in _SENTINEL_VERSIONS]


def collapse_affected_products(products: list[AffectedProduct]) -> list[AffectedProduct]:
    """Collapse many raw per-build/per-branch rows (as CVE.org and NVD often
    report one row per patch build) into a single compact row per distinct
    vendor+product, with one min-max affected range and a short fixed-version
    list — e.g. 70 pinned Cisco builds -> one 'Cisco Secure Firewall
    Management Center: 7.0.0 - 7.7.12' row."""
    if not products:
        return []

    groups: dict[tuple[str, str], list[AffectedProduct]] = {}
    for p in products:
        if not p.vendor or not p.product:
            continue
        vendor_key = _normalize_key(p.vendor)
        product_key = _normalize_key(p.product)
        # CVE.org sometimes repeats the vendor name inside the product field
        # ("Cisco" + "Cisco Secure Firewall...") - strip one leading copy so
        # this still groups with NVD's clean "Secure Firewall..." form.
        if product_key.startswith(vendor_key):
            product_key = product_key[len(vendor_key):]
        key = (vendor_key, product_key)
        groups.setdefault(key, []).append(p)

    collapsed: list[AffectedProduct] = []
    for rows in groups.values():
        vendor = display_vendor(rows[0].vendor)
        # Prefer the shortest product string in the group: CVE.org sometimes
        # duplicates the vendor name inside the product field (e.g. "Cisco
        # Cisco Secure Firewall Management Center (Fmc)") while NVD's CPE
        # data gives the clean form ("Cisco Secure Firewall Management
        # Center") - the shortest variant is reliably the cleaner one.
        product = display_product(min((r.product for r in rows), key=len))

        # Keep each distinct branch/range. A min/max rollup would mark gaps
        # between release branches as affected.
        ranges = list(dict.fromkeys(r.affected_range for r in rows if r.affected_range))
        affected_range = "; ".join(ranges) if ranges else "all versions"

        fixed_versions = sorted({r.fixed_version for r in rows if r.fixed_version}, key=_version_sort_key)

        collapsed.append(
            AffectedProduct(
                vendor=vendor,
                product=product,
                affected_range=affected_range,
                fixed_version=", ".join(fixed_versions[:_MAX_FIXED_VERSIONS_SHOWN])
                + ("…" if len(fixed_versions) > _MAX_FIXED_VERSIONS_SHOWN else "")
                if fixed_versions
                else None,
                status="affected",
            )
        )
    return collapsed


_BOUND_RE = re.compile(r"^(>=|>|<=|<)\s*(.+)$")


def version_in_range(version: str, range_part: str) -> bool:
    """Check whether `version` satisfies a single (non-multi-branch) range
    string as produced by `normalize_cpe_matches`, e.g. '>= 1.0, <= 1.2',
    '< 9.0.95', a bare pinned version like '1.0', or 'all versions'."""
    range_part = range_part.strip()
    if range_part.lower() == "all versions":
        return True

    bounds = [b.strip() for b in range_part.split(",") if b.strip()]
    if not bounds:
        return False
    if not _BOUND_RE.match(bounds[0]):
        # A bare version with no comparison operator is a pinned exact match.
        return _version_sort_key(version) == _version_sort_key(bounds[0])

    for bound in bounds:
        match = _BOUND_RE.match(bound)
        if not match:
            continue
        op, bound_version = match.group(1), match.group(2).strip()
        key, bound_key = _version_sort_key(version), _version_sort_key(bound_version)
        if op == ">=" and not key >= bound_key:
            return False
        if op == ">" and not key > bound_key:
            return False
        if op == "<=" and not key <= bound_key:
            return False
        if op == "<" and not key < bound_key:
            return False
    return True


def product_version_affected(affected_range: str | None, version: str) -> bool:
    """Check whether `version` falls in `affected_range`, which may combine
    several distinct branches joined by '; ' (as produced by
    `collapse_affected_products`)."""
    if not affected_range or not version:
        return False
    return any(version_in_range(version, part) for part in affected_range.split(";"))


def _product_label(p: AffectedProduct) -> str:
    """'{vendor} {product}', without repeating the vendor name when the
    product string (e.g. from CVE.org) already includes it."""
    if p.product.lower().startswith(p.vendor.lower()):
        return p.product
    return f"{p.vendor} {p.product}"


def summarize_affected_products(products: list[AffectedProduct]) -> tuple[str | None, str | None]:
    """Roll a list of (already-collapsed) AffectedProduct rows into two
    display strings for the 'Affected Versions' / 'Fixed Versions' columns."""
    if not products:
        return None, None
    affected = "; ".join(
        f"{_product_label(p)}: {p.affected_range}" for p in products if p.affected_range and p.affected_range != "all versions"
    ) or "; ".join(_product_label(p) for p in products)
    fixed_versions = sorted({p.fixed_version for p in products if p.fixed_version})
    fixed = "; ".join(fixed_versions) if fixed_versions else None
    return affected or None, fixed
