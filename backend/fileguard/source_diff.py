"""S4b: compare the published package against the source repository tag (static, nothing executed).

npm: package.json `repository` -> GitHub; PyPI: PKG-INFO/METADATA Project-URL / Home-page -> GitHub.
Tag candidates: v{ver}, {ver}, {name}@{ver}, {name}-v{ver}, {name}-{ver}, release-{ver}.
Downloads the tag tarball from codeload (size-capped) and diffs file lists / hashes / manifests.

Status: done | not_applicable (no repo declared / not a package) | unavailable (non-GitHub repo, tag not found)
        | failed (network error / stalled -> missing check, INCOMPLETE)
"""
import hashlib
import io
import json
import re
import tarfile
from pathlib import PurePosixPath

import httpx

from . import config

# files normally generated at publish time and absent from git
GENERATED = re.compile(r"(^|/)(dist|build|lib|es|esm|cjs|umd|types|typings|out|bundles?|_build)/|\.(min\.js|d\.ts|d\.mts|d\.cts|map|pyc)$"
                       r"|(^|/)(PKG-INFO|setup\.cfg|.*\.egg-info/.*|.*\.dist-info/.*)$|(^|/)(LICENSE|LICENCE|NOTICE|AUTHORS|CHANGELOG)[^/]*$|(^|/)(_?_?version_?_?|_build_info|__config__)\.(py|js|ts)$", re.I)
IGNORE_SAME = {"package.json", "PKG-INFO", "setup.cfg"}


def repo_from_npm(pj):
    r = pj.get("repository")
    url = r.get("url") if isinstance(r, dict) else r
    directory = r.get("directory") if isinstance(r, dict) else None
    if isinstance(url, str) and re.match(r"^[\w.-]+/[\w.-]+$", url):
        url = "https://github.com/" + url
    if isinstance(url, str) and url.startswith("github:"):
        url = "https://github.com/" + url[7:]
    return url, directory


def repo_from_pkginfo(text):
    for line in text.splitlines():
        m = re.match(r"^(Project-URL|Home-page|Download-URL):\s*(?:[^,]*,\s*)?(\S+)", line)
        if m and "github.com" in m.group(2):
            return m.group(2)
    return None


def slug(url):
    m = re.search(r"github\.com[/:]([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:[/#?]|$)", url or "")
    return (m.group(1), m.group(2)) if m else None


def run(ctx, eco, name, version, pkg_files, manifest, hook_paths):
    """pkg_files: {relative path inside the package root: sha256}. manifest: parsed package.json (npm) or PKG-INFO text."""
    res = {"check": "source_tag_diff", "status": "not_applicable"}
    if eco == "npm":
        url, sub = repo_from_npm(manifest or {})
    else:
        url, sub = repo_from_pkginfo(manifest or ""), None
    res["repository"] = url
    if not url:
        res.update(status="not_applicable", detail_zh="包没有声明源码仓库", detail_en="Package declares no source repository")
        return res
    s = slug(url)
    if not s:
        res.update(status="unavailable", detail_zh=f"源码仓库不在 GitHub（{url}），暂不支持比对", detail_en=f"Repository is not on GitHub ({url}); comparison unsupported")
        return res
    owner, repo = s
    short = name.split("/")[-1]
    tags = list(dict.fromkeys([f"v{version}", version, f"{name}@{version}", f"{short}@{version}", f"{short}-v{version}", f"{short}-{version}", f"release-{version}", f"{short}_v{version}"]))
    data, tag = None, None
    try:
        with httpx.Client(timeout=config.NET_STALL_TIMEOUT, follow_redirects=True) as c:
            for t in dict.fromkeys(tags):
                u = f"{config.CODELOAD_BASE}/{owner}/{repo}/tar.gz/refs/tags/{t}"
                with c.stream("GET", u) as r:
                    if r.status_code == 404:
                        continue
                    if r.status_code != 200:
                        raise IOError(f"HTTP {r.status_code}")
                    buf = io.BytesIO()
                    for ch in r.iter_bytes(1 << 16):
                        buf.write(ch)
                        if buf.tell() > config.MAX_REPO_TARBALL:
                            raise IOError("repo tarball too large")
                    data, tag = buf.getvalue(), t
                    break
    except Exception as e:
        res.update(status="failed", detail_zh=f"下载源码仓库 tag 失败（{type(e).__name__}: {str(e)[:80]}）", detail_en=f"Fetching repo tag failed ({type(e).__name__}: {str(e)[:80]})")
        return res
    if data is None:
        res.update(status="unavailable", detail_zh=f"仓库 {owner}/{repo} 中找不到与版本 {version} 对应的 tag（尝试了 {', '.join(tags[:4])} 等）",
                   detail_en=f"No tag matching version {version} in {owner}/{repo} (tried {', '.join(tags[:4])}, ...)")
        ctx.add("low", "S4", "SOURCE_TAG_MISSING", f"源码仓库没有与 {version} 对应的 tag，无法与源码比对", f"Source repo has no tag for {version}; cannot compare with source")
        return res
    repo_files, manifests, gitmodules = {}, {}, ""
    want = {PurePosixPath(p).name for p in pkg_files} | {"package.json", ".gitmodules"}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                parts = m.name.split("/", 1)
                if len(parts) < 2:
                    continue
                p = parts[1]
                base = PurePosixPath(p).name
                if base not in want or m.size > 20_000_000:
                    repo_files.setdefault(p, None)
                    continue
                b = tf.extractfile(m).read()
                repo_files[p] = hashlib.sha256(b).hexdigest()
                if base == "package.json" and eco == "npm" and "node_modules/" not in p:
                    try:
                        manifests[p] = json.loads(b)
                    except Exception:
                        pass
                if p == ".gitmodules":
                    gitmodules = b.decode("utf-8", "replace")
    except Exception as e:
        res.update(status="failed", detail_zh=f"源码 tag 压缩包解析失败（{type(e).__name__}）", detail_en=f"Repo tag tarball parse failed ({type(e).__name__})")
        return res
    # monorepos: use the directory whose package.json has the same name (or the declared repository.directory)
    repo_manifest = None
    if eco == "npm":
        cand = [k for k, v in manifests.items() if isinstance(v, dict) and v.get("name") == name]
        key = (sub.rstrip("/") + "/package.json") if sub else None
        key = key if key in manifests else (sorted(cand, key=len)[0] if cand else ("package.json" if "package.json" in manifests else None))
        if key:
            repo_manifest = manifests[key]
            d = key.rsplit("/", 1)[0] if "/" in key else ""
            if d and not sub:
                sub = d
    if sub:
        pre = sub.rstrip("/") + "/"
        scoped = {k[len(pre):]: v for k, v in repo_files.items() if k.startswith(pre)}
        repo_files = {**repo_files, **scoped}     # keep full paths too (files may be copied from elsewhere at build)
    # git submodules are not contained in tag tarballs: exclude them from the comparison
    submods = re.findall(r"^\s*path\s*=\s*(.+?)\s*$", gitmodules, re.M)
    excluded = [p for p in pkg_files if any(p == sm or p.startswith(sm.rstrip("/") + "/") for sm in submods)]
    pkg_files = {k: v for k, v in pkg_files.items() if k not in set(excluded)}
    res["submodule_files_excluded"] = len(excluded)
    repo_hashes = {v for v in repo_files.values() if v}
    suffixes = {}
    for rp in repo_files:
        parts = rp.split("/")
        for k in range(1, len(parts)):
            suffixes.setdefault("/".join(parts[k:]), rp)

    def in_repo(p):   # exact path, same content anywhere (moved), or src-layout suffix match
        return p in repo_files or pkg_files[p] in repo_hashes or p in suffixes
    only_pkg = sorted(p for p in pkg_files if not in_repo(p))
    unexpected = [p for p in only_pkg if not GENERATED.search(p)]
    changed = sorted(p for p in pkg_files if p in repo_files and repo_files[p] and pkg_files[p] != repo_files[p] and p not in IGNORE_SAME and not GENERATED.search(p))
    hook_only = sorted(p for p in pkg_files if p in hook_paths and p not in repo_files and pkg_files[p] not in repo_hashes)
    res.update(status="done", tag=tag, repo=f"{owner}/{repo}", files_only_in_package=only_pkg[:100], unexpected_files=unexpected[:100],
               changed_files=changed[:100], package_files=len(pkg_files), repo_files=len(repo_files),
               detail_zh=f"已与 {owner}/{repo}@{tag} 比对（包内 {len(pkg_files)} 个文件）：包中独有 {len(only_pkg)} 个文件（非构建产物 {len(unexpected)} 个），内容不同 {len(changed)} 个",
               detail_en=f"Compared with {owner}/{repo}@{tag} ({len(pkg_files)} package files): {len(only_pkg)} files only in package ({len(unexpected)} non-generated), {len(changed)} changed")
    declared = {}
    if eco == "npm" and repo_manifest is not None and isinstance(repo_manifest.get("scripts"), dict):
        declared = {h: c for h, c in repo_manifest["scripts"].items() if h in ("preinstall", "install", "postinstall")}
    for p in hook_only:
        if any(p in str(c) for c in declared.values()):
            ctx.add("low", "S4", "SOURCE_DIFF_HOOK_SCRIPT_GENERATED", f"安装钩子脚本 {p} 不在源码 tag 中，但源码中的 package.json 声明了同一钩子（构建时生成）",
                    f"Install-hook script {p} is not in the repo tag, but the repo package.json declares the same hook (generated at build)", p, tag)
            continue
        ctx.add("high", "S4", "SOURCE_DIFF_HOOK_NOT_IN_REPO", f"安装钩子执行的 {p} 只存在于发布包，源码仓库 tag {tag} 中没有（发布时被注入）",
                f"Install-hook script {p} exists only in the published package, not in repo tag {tag} (injected at publish)", p, tag)
    if eco == "npm" and repo_manifest is not None:
        ps = (manifest.get("scripts") or {}) if isinstance(manifest.get("scripts"), dict) else {}
        rs = (repo_manifest.get("scripts") or {}) if isinstance(repo_manifest.get("scripts"), dict) else {}
        for h in ("preinstall", "install", "postinstall", "prepare"):
            if ps.get(h) and ps.get(h) != rs.get(h):
                ctx.add("high", "S4", "SOURCE_DIFF_HOOK_ADDED", f"发布包的 {h} 钩子与源码 tag 不同或源码中没有：{ps[h][:100]}",
                        f"Published {h} hook differs from / is absent in the repo tag: {ps[h][:100]}", "package.json", ps[h][:100])
        pd = {**(manifest.get("dependencies") or {}), **(manifest.get("optionalDependencies") or {})}
        rd = {**(repo_manifest.get("dependencies") or {}), **(repo_manifest.get("optionalDependencies") or {})}
        added = sorted(set(pd) - set(rd))
        if added:
            ctx.add("high", "S4", "SOURCE_DIFF_DEP_ADDED", f"发布包新增了源码 tag 中没有的依赖：{', '.join(added)}（Axios 投毒正是这样注入的）",
                    f"Published package adds dependencies absent from the repo tag: {', '.join(added)} (exactly how the Axios compromise was injected)", "package.json", ", ".join(added))
        res["deps_added_vs_repo"] = added
    code_unexpected = [p for p in unexpected if re.search(r"\.(js|cjs|mjs|py|sh|ps1|bat|cmd|exe|dll|so|node)$", p) and p not in hook_only]
    res["unexpected_code_files"] = code_unexpected[:100]
    if len(code_unexpected) > 10:   # bulk differences = a build step (e.g. modularised bundles), reported only
        ctx.add("info", "S4", "SOURCE_DIFF_BULK_BUILD_OUTPUT", f"发布包有 {len(code_unexpected)} 个源码 tag 中没有的代码文件（数量大，像构建产物）",
                f"Published package has {len(code_unexpected)} code files not in the repo tag (bulk; looks like build output)")
    elif code_unexpected:
        ctx.add("medium", "S4", "SOURCE_DIFF_EXTRA_CODE", f"发布包包含源码 tag 中没有的代码文件（非常见构建产物）：{', '.join(code_unexpected[:5])}",
                f"Published package contains code files absent from the repo tag (not typical build output): {', '.join(code_unexpected[:5])}", None, ", ".join(code_unexpected[:5]))
    return res
