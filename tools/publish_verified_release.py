#!/usr/bin/env python3
"""Publish a pre-signed APK from a pinned Git blob; never build or sign an application."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "hp5588/pocket-fx-downloads"
API = "https://api.github.com"


def api(path, method="GET", data=None):
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(API + path, data=body, method=method, headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "PocketFx-release-publisher",
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def upload(release_id, path):
    request = urllib.request.Request(
        f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?"
        + urllib.parse.urlencode({"name": path.name}),
        data=path.read_bytes(), method="POST", headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Content-Type": "application/octet-stream",
            "Accept": "application/vnd.github+json",
        })
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def digests(release):
    return {item["name"]: item.get("digest") for item in release["assets"]}


def main():
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Publication is restricted to the distribution repository main branch")
    if api(f"/repos/{REPOSITORY}")["private"]:
        raise ValueError("The distribution repository must be public")
    manifest = json.loads((ROOT / "release/v0.3.4.json").read_text())
    version = manifest["version"]
    if version != "0.3.4" or manifest["version_code"] != 12 or manifest["tag"] != "v0.3.4" or manifest["apk_name"] != "pocket-fx-0.3.4.apk":
        raise ValueError("Unexpected release target")
    expected_sha = manifest["apk_sha256"]
    certificate = manifest["certificate_sha256"]
    if not all(re.fullmatch(r"[0-9a-f]{64}", x) for x in [expected_sha, certificate]):
        raise ValueError("Invalid expected fingerprints")
    filename = manifest["apk_name"]
    sums = f"{expected_sha}  {filename}\n".encode()
    expected = {filename: "sha256:" + expected_sha, "SHA256SUMS.txt": "sha256:" + hashlib.sha256(sums).hexdigest()}
    tag = manifest["tag"]
    existing = None
    page = 1
    while True:
        releases = api(f"/repos/{REPOSITORY}/releases?per_page=100&page={page}")
        existing = next((r for r in releases if r["tag_name"] == tag), None)
        if existing or len(releases) < 100:
            break
        page += 1
    if existing and not existing["draft"]:
        if existing["prerelease"] or digests(existing) != expected:
            raise ValueError("Published release differs; refusing replacement")
        print("Existing release verified:", existing["html_url"])
        return
    if existing and existing["target_commitish"] != os.environ["GITHUB_SHA"]:
        raise ValueError("Draft belongs to a different commit; refusing replacement")

    blob = api(f'/repos/{REPOSITORY}/git/blobs/{manifest["apk_blob_sha"]}')
    if blob["encoding"] != "base64" or blob["size"] != manifest["apk_bytes"] or blob["size"] > 20 * 1024 * 1024:
        raise ValueError("Unexpected staged APK size or encoding")
    data = base64.b64decode("".join(blob["content"].split()), validate=True)
    if len(data) != manifest["apk_bytes"] or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("Staged APK digest mismatch")
    sdk = Path(os.environ["ANDROID_HOME"]) / "build-tools/35.0.0"
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory)
        apk = output / filename
        apk.write_bytes(data)
        signed = subprocess.check_output([str(sdk / "apksigner"), "verify", "--verbose", "--print-certs", str(apk)], text=True, timeout=30)
        fingerprints = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$", signed, re.M)
        if fingerprints != [certificate] or "Verified using v2 scheme (APK Signature Scheme v2): true" not in signed:
            raise ValueError("APK release identity mismatch")
        badging = subprocess.check_output([str(sdk / "aapt"), "dump", "badging", str(apk)], text=True, timeout=30)
        if not badging.startswith("package: name='io.github.hp5588.pocketfx' versionCode='12' versionName='0.3.4' ") or "application-debuggable" in badging:
            raise ValueError("APK version or release build mismatch")
        permissions = subprocess.check_output([str(sdk / "aapt"), "dump", "permissions", str(apk)], text=True, timeout=30)
        names = set(re.findall(r"uses-permission: name='([^']+)'", permissions))
        allowed = {"android.permission.INTERNET", "io.github.hp5588.pocketfx.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"}
        if "android.permission.INTERNET" not in names or not names <= allowed:
            raise ValueError("Unexpected APK permissions")
        checksums = output / "SHA256SUMS.txt"
        checksums.write_bytes(sums)
        release = existing or api(f"/repos/{REPOSITORY}/releases", "POST", {
            "tag_name": tag, "target_commitish": os.environ["GITHUB_SHA"],
            "name": "口袋汇率 " + version,
            "body": (ROOT / "release/NOTES-0.3.4.md").read_text(),
            "draft": True, "prerelease": False,
        })
        assets = digests(release)
        for path in [apk, checksums]:
            if path.name in assets:
                if assets[path.name] != expected[path.name]:
                    raise ValueError("Existing draft asset differs; refusing replacement")
            elif upload(release["id"], path).get("digest") != expected[path.name]:
                raise ValueError("Uploaded asset digest mismatch")
        uploaded = api(f'/repos/{REPOSITORY}/releases/{release["id"]}')
        if digests(uploaded) != expected:
            raise ValueError("Incomplete or unexpected release assets")
        api(f'/repos/{REPOSITORY}/releases/{release["id"]}', "PATCH", {"draft": False, "prerelease": False})
        published = api(f"/repos/{REPOSITORY}/releases/tags/{tag}")
        if published["draft"] or published["prerelease"] or digests(published) != expected:
            raise ValueError("Published release verification failed")
        print("Published release:", published["html_url"])
        print("APK SHA-256:", expected_sha)


if __name__ == "__main__":
    main()
