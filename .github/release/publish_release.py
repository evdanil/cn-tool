#!/usr/bin/env python3
"""Checks for the Release workflow (.github/workflows/release.yml): standard library only.

A commit pushed to main asks for a release in its message:

    [Release - X.Y.Z]
    wheel-sha256: <64 hex digits>
    sdist-sha256: <64 hex digits>

The digests are those of the verified build. The workflow builds the wheel and the sdist again from the commit's own
tree (the build is reproducible) and releases only those exact bytes, so the GitHub release and PyPI carry the same
files. Every check fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

VERSION = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
MARKER = re.compile(r'\[Release - (' + VERSION + r')\]')
DIGEST = {'wheel': re.compile(r'^wheel-sha256: ([0-9a-f]{64})$', re.M),
          'sdist': re.compile(r'^sdist-sha256: ([0-9a-f]{64})$', re.M)}
ZIP = 'cn-tool-generic.zip'


class ReleaseError(Exception):
    """A release check failed: nothing may be published."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def parse_request(message: str) -> dict[str, str]:
    """The version and the two digests the commit message asks for: each exactly once."""
    versions = MARKER.findall(message)
    require(len(versions) == 1, 'the commit message must name exactly one [Release - X.Y.Z]')
    request = {'version': versions[0]}
    for name, pattern in DIGEST.items():
        found = pattern.findall(message)
        require(len(found) == 1, f'the commit message must give exactly one {name}-sha256 line')
        request[f'{name}_sha256'] = found[0]
    return request


def tree_version(root: Path) -> str:
    """MAJOR.MINOR.BUILD from cn_tool/version, the file the build and cn --version read."""
    fields: dict[str, str] = {}
    for line in (root / 'cn_tool' / 'version').read_text(encoding='ascii').splitlines():
        key, separator, value = line.partition('=')
        require(bool(separator) and key not in fields, 'invalid cn_tool/version')
        fields[key] = value
    require(set(fields) == {'MAJOR', 'MINOR', 'BUILD', 'BUILD_HASH'}, 'invalid cn_tool/version')
    version = '.'.join(fields[key] for key in ('MAJOR', 'MINOR', 'BUILD'))
    require(re.fullmatch(VERSION, version) is not None, 'invalid cn_tool/version')
    return version


def distribution_names(version: str) -> tuple[str, str]:
    return f'cn_tool-{version}-py3-none-any.whl', f'cn_tool-{version}.tar.gz'


def release_notes(document: str, version: str) -> str:
    """The "## X.Y.Z" section of docs/release-notes.md, without its heading."""
    match = re.search(rf'^## {re.escape(version)}\n(.*?)(?=^## |\Z)', document, re.M | re.S)
    require(match is not None, f'docs/release-notes.md has no "## {version}" section')
    notes = match.group(1).strip()
    require(bool(notes), f'the "## {version}" section of docs/release-notes.md is empty')
    return notes


def check_distributions(directory: Path, request: dict[str, str]) -> None:
    """The build made exactly the wheel and the sdist the message names, byte for byte."""
    wheel, sdist = distribution_names(request['version'])
    found = sorted(path.name for path in directory.iterdir())
    require(found == sorted([wheel, sdist]), f'unexpected build output: {found}')
    for name, key in ((wheel, 'wheel_sha256'), (sdist, 'sdist_sha256')):
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f'{name} is not a regular file')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == request[key], f'{name} is not the verified build: sha256 {digest}')


def api(path: str) -> object | None:
    """GET from the GitHub API: the JSON, or None for a 404. Anything else fails."""
    request = urllib.request.Request(
        f'https://api.github.com/{path}',
        headers={'Accept': 'application/vnd.github+json', 'Authorization': f'Bearer {os.environ["GH_TOKEN"]}',
                 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise ReleaseError(f'GitHub API {path}: HTTP {error.code}') from error


def check_unreleased(repository: str, sha: str, version: str) -> None:
    """The commit is still the head of main, and neither the tag nor a release for it exists yet."""
    head = api(f'repos/{repository}/git/ref/heads/main')
    require(isinstance(head, dict) and head.get('object', {}).get('sha') == sha, 'main has moved on from this commit')
    require(api(f'repos/{repository}/git/ref/tags/v{version}') is None, f'tag v{version} already exists')
    require(api(f'repos/{repository}/releases/tags/v{version}') is None, f'a release for v{version} already exists')


def check_published(release: object, sha: str, tag_commit: str, request: dict[str, str]) -> None:
    """The published release is the one asked for: its tag at this commit and the verified bytes as assets."""
    version = request['version']
    require(isinstance(release, dict), 'the release cannot be read')
    require(release.get('tag_name') == f'v{version}' and release.get('draft') is False
            and release.get('prerelease') is False and bool(release.get('published_at')),
            'the release is not the published v' + version)
    require(tag_commit == sha, f'tag v{version} does not point at this commit')
    wheel, sdist = distribution_names(version)
    assets = {asset.get('name'): asset for asset in release.get('assets') or []}
    require(set(assets) == {ZIP, wheel, sdist}, f'unexpected release assets: {sorted(assets)}')
    for name, key in ((wheel, 'wheel_sha256'), (sdist, 'sdist_sha256')):
        asset = assets[name]
        require(asset.get('state') == 'uploaded' and asset.get('digest') == 'sha256:' + request[key],
                f'release asset {name} is not the verified build')


def tag_commit(repository: str, version: str) -> str:
    obj = (api(f'repos/{repository}/git/ref/tags/v{version}') or {}).get('object', {})
    for _ in range(8):
        if obj.get('type') == 'commit':
            return obj.get('sha', '')
        require(obj.get('type') == 'tag', 'unsupported tag object')
        obj = (api(f'repos/{repository}/git/tags/{obj.get("sha")}') or {}).get('object', {})
    raise ReleaseError('tag chain too deep')


def main(argv: list[str]) -> int:
    env = os.environ
    root = Path.cwd()
    try:
        request = parse_request(env['COMMIT_MESSAGE'])
        version = request['version']
        command = argv[1:2]
        if command == ['request']:
            require(tree_version(root) == version, f'cn_tool/version is {tree_version(root)}, not {version}')
            notes = release_notes((root / 'docs' / 'release-notes.md').read_text(encoding='utf-8'), version)
            Path(argv[2]).write_text(f'# cn-tool {version}\n\n{notes}\n', encoding='utf-8')
            check_unreleased(env['GITHUB_REPOSITORY'], env['GITHUB_SHA'], version)
            with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
                output.write(f'version={version}\n')
        elif command == ['distributions']:
            check_distributions(Path(argv[2]), request)
        elif command == ['ready']:
            # Again on the line before the release is created: main may have moved during the build.
            check_unreleased(env['GITHUB_REPOSITORY'], env['GITHUB_SHA'], version)
        elif command == ['published']:
            release = api(f'repos/{env["GITHUB_REPOSITORY"]}/releases/tags/v{version}')
            check_published(release, env['GITHUB_SHA'], tag_commit(env['GITHUB_REPOSITORY'], version), request)
        else:
            raise ReleaseError('usage: publish_release.py request NOTES | distributions DIR | ready | published')
    except (ReleaseError, KeyError, OSError, ValueError) as error:
        print(f'::error::release refused: {error}')
        return 1
    print('release check passed')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
