"""S3a: safe recursive archive unpacking. Never executes anything.

Guards: max depth, total unpacked bytes budget, file-count cap, per-entry compression ratio
(zip-bomb heuristic), path traversal (Zip Slip), symlinks/hardlinks/devices, encrypted entries,
corrupt archives. Anything not inspected is recorded as a Missing item (-> INCOMPLETE).
"""
import bz2
import gzip
import lzma
import os
import re
import resource
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

from . import config, tools

CHUNK = 1 << 16


def sniff(path):
    """Identify container type by magic bytes (extension is never trusted)."""
    try:
        with open(path, "rb") as f:
            head = f.read(600)
    except OSError:
        return None
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:7] == b"Rar!\x1a\x07\x00" or head[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:3] == b"BZh":
        return "bz2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if head[:8] == b"!<arch>\n":
        return "ar"      # .deb
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return "zst"     # e.g. control.tar.zst / data.tar.zst inside modern .deb files
    if head[:4] == b"\xed\xab\xee\xdb":
        return "rpm"
    if head[:2] == b"MZ":
        from .installers import pe_installer_kind
        if pe_installer_kind(path) == "nsis":
            return "nsis"
    if head[:4] == b"\xd0\xcf\x11\xe0" and str(path).lower().endswith(".msi"):
        return None
    return None


def _bad_name(name):
    n = name.replace("\\", "/")
    return n.startswith("/") or re.match(r"^[A-Za-z]:", n) is not None or ".." in n.split("/")


def _safe_rel(name):
    n = name.replace("\\", "/")
    n = re.sub(r"^[A-Za-z]:", "", n)
    parts = [p for p in n.split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "unnamed"


class Unpacker:
    def __init__(self, ctx, out_root):
        self.ctx = ctx
        self.out_root = Path(out_root)
        self.total = 0
        self.count = 0
        self.inventory = []   # list of dict(rel, abs, size, depth, parent, container)
        self._n = 0
        self.stats = {"archives_unpacked": 0, "archives_failed": 0, "entries_skipped": 0}
        self._kinds = {}      # rel -> container kind, for context (e.g. "is this tar a .deb payload?")

    # ---- helpers -------------------------------------------------------
    def _newdir(self):
        self._n += 1
        d = self.out_root / f"x{self._n:05d}"
        d.mkdir(parents=True)
        return d

    def _budget_left(self):
        return config.MAX_UNPACK_TOTAL_BYTES - self.total

    def _over_budget(self, rel, declared=None, ratio=None):
        c = self.ctx
        c.miss("S3", "UNPACK_SIZE_LIMIT",
               f"解压总量超过上限 {config.MAX_UNPACK_TOTAL_BYTES // (1 << 20)} MB，剩余内容未检测",
               f"Total unpacked size limit {config.MAX_UNPACK_TOTAL_BYTES // (1 << 20)} MB reached; remaining content not inspected", rel)
        if ratio and ratio >= config.BOMB_RATIO:
            c.add("high", "S3", "ARCHIVE_DECOMPRESSION_BOMB",
                  f"疑似压缩炸弹：压缩比约 {ratio:.0f}:1，声明解压大小 {declared} 字节",
                  f"Suspected decompression bomb: ratio ~{ratio:.0f}:1, declared unpacked size {declared} bytes", rel)

    def _copy_stream(self, src, dst_path, limit):
        """Copy at most `limit` bytes; return (written, truncated)."""
        written = 0
        with open(dst_path, "wb") as out:
            while True:
                if self.ctx.deadline:
                    self.ctx.deadline()
                chunk = src.read(CHUNK)
                if not chunk:
                    return written, False
                if written + len(chunk) > limit:
                    out.write(chunk[: max(0, limit - written)])
                    return limit, True
                out.write(chunk)
                written += len(chunk)

    def _register(self, abs_path, rel, depth, parent, container):
        size = os.path.getsize(abs_path)
        self.count += 1
        self.inventory.append({"rel": rel, "abs": str(abs_path), "size": size, "depth": depth,
                               "parent": parent, "container": container})

    def _count_ok(self, rel):
        if self.count >= config.MAX_UNPACK_FILES:
            self.ctx.miss("S3", "UNPACK_FILE_COUNT_LIMIT", f"解压文件数量超过上限 {config.MAX_UNPACK_FILES}",
                          f"Unpacked file count exceeds {config.MAX_UNPACK_FILES}", rel)
            return False
        return True

    # ---- main entry ----------------------------------------------------
    def run(self, sample_path, display_name):
        self._register(sample_path, display_name, 0, None, None)
        queue = [self.inventory[0]]
        while queue:
            item = queue.pop(0)
            kind = sniff(item["abs"])
            if not kind:
                continue
            item["container"] = kind
            self._kinds[item["rel"]] = kind
            if item["depth"] >= config.MAX_UNPACK_DEPTH:
                self.ctx.miss("S3", "UNPACK_DEPTH_LIMIT",
                              f"嵌套压缩超过 {config.MAX_UNPACK_DEPTH} 层，内层内容未检测",
                              f"Nested archive deeper than {config.MAX_UNPACK_DEPTH} levels; inner content not inspected", item["rel"])
                continue
            before = len(self.inventory)
            try:
                getattr(self, f"_x_{kind}")(item)
                self.stats["archives_unpacked"] += 1
            except _Corrupt as e:
                self.stats["archives_failed"] += 1
                self.ctx.miss("S3", "ARCHIVE_CORRUPT", f"压缩包损坏或无法解析（{e}），内容未检测",
                              f"Archive is corrupt or unparseable ({e}); contents not inspected", item["rel"])
            queue.extend(self.inventory[before:])
        return self.inventory

    # ---- format handlers ----------------------------------------------
    def _x_zip(self, item):
        rel0, d = item["rel"], None
        try:
            zf = zipfile.ZipFile(item["abs"])
        except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as e:
            raise _Corrupt(type(e).__name__)
        with zf:
            infos = zf.infolist()
            declared_total = sum(i.file_size for i in infos)
            comp_total = sum(i.compress_size for i in infos) or 1
            if declared_total > self._budget_left():
                self._over_budget(rel0, declared_total, declared_total / comp_total)
                return
            d = self._newdir()
            for info in infos:
                name = info.filename
                rel = f"{rel0}!/{name}"
                if info.is_dir():
                    continue
                if not self._count_ok(rel):
                    return
                if _bad_name(name):
                    self.ctx.add("high", "S3", "ARCHIVE_PATH_TRAVERSAL",
                                 f"压缩包条目包含路径穿越（Zip Slip）：{name}",
                                 f"Archive entry uses path traversal (Zip Slip): {name}", rel0, name)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    self.ctx.add("medium", "S3", "ARCHIVE_SYMLINK", f"压缩包包含符号链接条目：{name}",
                                 f"Archive contains a symlink entry: {name}", rel0, name)
                    self.stats["entries_skipped"] += 1
                    continue
                if info.flag_bits & 0x1:
                    self.ctx.miss("S3", "ARCHIVE_ENCRYPTED", f"加密的压缩条目无法检测：{name}",
                                  f"Encrypted archive entry cannot be inspected: {name}", rel)
                    self.stats["entries_skipped"] += 1
                    continue
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio >= config.BOMB_RATIO and info.file_size > 50 * (1 << 20):
                    self.ctx.add("high", "S3", "ARCHIVE_DECOMPRESSION_BOMB",
                                 f"疑似压缩炸弹条目：压缩比约 {ratio:.0f}:1", f"Suspected bomb entry: ratio ~{ratio:.0f}:1", rel)
                left = self._budget_left()
                if left <= 0:
                    self._over_budget(rel, declared_total, declared_total / comp_total)
                    return
                dst = d / f"{len(self.inventory):06d}_{Path(_safe_rel(name)).name[:120]}"
                try:
                    with zf.open(info) as src:
                        n, trunc = self._copy_stream(src, dst, min(left, info.file_size + 1))
                except (zipfile.BadZipFile, zlib_error(), EOFError, OSError, NotImplementedError, RuntimeError) as e:
                    self.ctx.miss("S3", "ARCHIVE_ENTRY_CORRUPT", f"压缩条目损坏无法读取（{type(e).__name__}）：{name}",
                                  f"Archive entry corrupt/unreadable ({type(e).__name__}): {name}", rel)
                    dst.unlink(missing_ok=True)
                    continue
                if trunc:
                    if n >= left:
                        self.total += n
                        self._over_budget(rel, declared_total, declared_total / comp_total)
                        dst.unlink(missing_ok=True)
                        return
                    self.ctx.add("high", "S3", "ARCHIVE_SIZE_MISMATCH", f"条目实际大小超过声明大小（头部伪造）：{name}",
                                 f"Entry larger than its declared size (forged header): {name}", rel)
                self.total += n
                self._register(dst, rel, item["depth"] + 1, rel0, None)

    def _deb_payload(self, rel):
        """True if `rel` is (a decompressed form of) the data.tar member of a .deb. dpkg installs that
        payload relative to /, so absolute symlink targets there are normal, not an archive escape."""
        parts = rel.split("!/")
        for i in range(len(parts) - 1):
            if self._kinds.get("!/".join(parts[: i + 1])) == "ar":
                return parts[i + 1].startswith("data.tar") and all("data.tar" in p for p in parts[i + 1:])
        return False

    def _x_tar(self, item):
        rel0 = item["rel"]
        deb_payload = self._deb_payload(rel0)
        try:
            tf = tarfile.open(item["abs"], mode="r:*")
        except (tarfile.TarError, OSError, EOFError, lzma.LZMAError) as e:
            raise _Corrupt(type(e).__name__)
        d = self._newdir()
        try:
            with tf:
                for m in tf:
                    name = m.name
                    rel = f"{rel0}!/{name}"
                    if _bad_name(name):
                        self.ctx.add("high", "S3", "ARCHIVE_PATH_TRAVERSAL", f"tar 条目包含路径穿越：{name}",
                                     f"Tar entry uses path traversal: {name}", rel0, name)
                    if m.issym() or m.islnk():
                        target = m.linkname
                        if deb_payload and m.issym() and target.startswith("/") and not _bad_name(name):
                            continue
                        if _link_escapes(name, target, m.islnk()):
                            self.ctx.add("high", "S3", "ARCHIVE_LINK_ESCAPE", f"tar 链接指向包外：{name} -> {target}",
                                         f"Tar link points outside archive: {name} -> {target}", rel0, f"{name} -> {target}")
                        continue
                    if m.isdev() or m.isfifo():
                        self.ctx.add("medium", "S3", "ARCHIVE_DEVICE", f"tar 包含设备/管道文件：{name}",
                                     f"Tar contains device/FIFO entry: {name}", rel0, name)
                        continue
                    if not m.isfile():
                        continue
                    if not self._count_ok(rel):
                        return
                    if m.mode & 0o4000:
                        self.ctx.add("medium", "S3", "ARCHIVE_SETUID", f"tar 中文件带 setuid 位：{name}",
                                     f"Tar entry has setuid bit: {name}", rel0, name)
                    left = self._budget_left()
                    if m.size > left:
                        csize = os.path.getsize(item["abs"]) or 1
                        self._over_budget(rel, self.total + m.size, (self.total + m.size) / csize)
                        return
                    dst = d / f"{len(self.inventory):06d}_{Path(_safe_rel(name)).name[:120]}"
                    src = tf.extractfile(m)
                    if src is None:
                        continue
                    n, _ = self._copy_stream(src, dst, m.size)
                    self.total += n
                    self._register(dst, rel, item["depth"] + 1, rel0, None)
        except (tarfile.TarError, OSError, EOFError, lzma.LZMAError, zlib_error()) as e:
            raise _Corrupt(type(e).__name__)

    def _single_stream(self, item, opener):
        rel0 = item["rel"]
        # compressed tarball?
        try:
            if tarfile.is_tarfile(item["abs"]):
                return self._x_tar(item)
        except Exception:
            pass
        d = self._newdir()
        base = Path(item["rel"].split("!/")[-1]).name
        inner = re.sub(r"\.(gz|tgz|bz2|xz|txz|z)$", "", base, flags=re.I) or "stream"
        dst = d / f"{len(self.inventory):06d}_{inner[:120]}"
        left = self._budget_left()
        try:
            with opener(item["abs"]) as src:
                n, trunc = self._copy_stream(src, dst, left)
        except (OSError, EOFError, lzma.LZMAError, zlib_error()) as e:
            dst.unlink(missing_ok=True)
            raise _Corrupt(type(e).__name__)
        if trunc:
            csize = os.path.getsize(item["abs"]) or 1
            self.total += n
            self._over_budget(rel0, f">{n}", n / csize)
            dst.unlink(missing_ok=True)
            return
        self.total += n
        self._register(dst, f"{rel0}!/{inner}", item["depth"] + 1, rel0, None)

    def _x_gz(self, item):
        return self._single_stream(item, gzip.open)

    def _x_bz2(self, item):
        return self._single_stream(item, bz2.open)

    def _x_xz(self, item):
        return self._single_stream(item, lzma.open)

    # 7z / rar / rpm / zstd via the 7z CLI (ar/.deb is parsed in Python, see _x_ar) (list first, then extract with limits)
    def _x_7z(self, item):
        return self._via_7z(item)

    def _x_rar(self, item):
        return self._via_7z(item)

    def _x_ar(self, item):
        """Unix ar (.deb) parsed in Python. 7-Zip treats a .deb as a single package and only exposes
        data.tar, hiding control.tar.* (maintainer scripts), so it must not be used here."""
        rel0 = item["rel"]
        try:
            members = list(_ar_members(item["abs"]))
        except (OSError, ValueError) as e:
            raise _Corrupt(f"ar: {e}"[:120])
        declared = sum(size for _, _, size in members)
        if declared > self._budget_left():
            csize = os.path.getsize(item["abs"]) or 1
            self._over_budget(rel0, declared, declared / csize)
            return
        d = self._newdir()
        with open(item["abs"], "rb") as f:
            for name, offset, size in members:
                rel = f"{rel0}!/{name}"
                if _bad_name(name):
                    self.ctx.add("high", "S3", "ARCHIVE_PATH_TRAVERSAL", f"ar 条目包含路径穿越：{name}",
                                 f"ar entry uses path traversal: {name}", rel0, name)
                if not self._count_ok(rel):
                    return
                left = self._budget_left()
                if size > left:
                    self._over_budget(rel)
                    return
                dst = d / f"{len(self.inventory):06d}_{Path(_safe_rel(name)).name[:120]}"
                f.seek(offset)
                n, _ = self._copy_stream(_Bounded(f, size), dst, size)
                if n != size:
                    dst.unlink(missing_ok=True)
                    raise _Corrupt(f"ar member {name} truncated")
                self.total += n
                self._register(dst, rel, item["depth"] + 1, rel0, None)

    def _x_zst(self, item):
        return self._via_7z(item)

    def _x_rpm(self, item):
        return self._via_7z(item)

    def _x_nsis(self, item):
        return self._via_7z(item)

    def _via_7z(self, item):
        rel0 = item["rel"]
        exe = tools.sevenzip()
        if not exe:
            self.ctx.miss("S3", "UNPACK_TOOL_MISSING", "缺少 7z 工具，无法解包", "7z tool missing; cannot unpack", rel0)
            return
        try:
            p = tools.run_limited([exe, "l", "-slt", "-ba", "-pFG_NO_PASSWORD", "--", item["abs"]],
                                  capture_output=True, text=True, timeout=120, errors="replace")
        except subprocess.TimeoutExpired:
            raise _Corrupt("list timeout")
        out = p.stdout
        if p.returncode != 0 and not out.strip():
            if "Wrong password" in p.stderr or "encrypted" in p.stderr.lower():
                self.ctx.miss("S3", "ARCHIVE_ENCRYPTED", "压缩包已加密（含文件名加密），无法检测",
                              "Archive is encrypted (headers encrypted); cannot inspect", rel0)
                return
            raise _Corrupt((p.stderr.strip().splitlines() or ["7z list failed"])[-1][:120])
        entries, cur = [], {}
        for line in out.splitlines():
            if not line.strip():
                if cur:
                    entries.append(cur)
                cur = {}
                continue
            if " = " in line:
                k, v = line.split(" = ", 1)
                cur[k.strip()] = v.strip()
        if cur:
            entries.append(cur)
        declared = 0
        encrypted_any = False
        for e in entries:
            name = e.get("Path", "")
            if _bad_name(name):
                self.ctx.add("high", "S3", "ARCHIVE_PATH_TRAVERSAL", f"压缩包条目包含路径穿越：{name}",
                             f"Archive entry uses path traversal: {name}", rel0, name)
            if e.get("Encrypted") == "+":
                encrypted_any = True
                self.ctx.miss("S3", "ARCHIVE_ENCRYPTED", f"加密的压缩条目无法检测：{name}",
                              f"Encrypted archive entry cannot be inspected: {name}", f"{rel0}!/{name}")
            try:
                declared += int(e.get("Size") or 0)
            except ValueError:
                pass
        if declared > self._budget_left():
            csize = os.path.getsize(item["abs"]) or 1
            self._over_budget(rel0, declared, declared / csize)
            return
        d = self._newdir()
        left = self._budget_left()

        try:
            p = tools.run_limited([exe, "x", "-y", "-snl-", "-pFG_NO_PASSWORD", f"-o{d}", "--", item["abs"]],
                                  capture_output=True, text=True, timeout=600, fsize=left + 1, errors="replace")
        except subprocess.TimeoutExpired:
            self.ctx.miss("S3", "UNPACK_TIMEOUT", "解包超时，内容未完整检测", "Unpacking timed out; contents not fully inspected", rel0)
            return
        if p.returncode not in (0, 1) and not encrypted_any:
            msg = (p.stderr.strip().splitlines() or ["7z extract failed"])[-1][:160]
            self.ctx.miss("S3", "ARCHIVE_CORRUPT", f"压缩包部分条目无法解出（{msg}）",
                          f"Some archive entries could not be extracted ({msg})", rel0)
        root = d.resolve()
        for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.is_symlink() or not fp.resolve().is_relative_to(root):
                    self.ctx.add("medium", "S3", "ARCHIVE_SYMLINK", f"解包得到符号链接或越界文件：{fn}",
                                 f"Unpacked symlink / out-of-tree file: {fn}", rel0, fn)
                    fp.unlink(missing_ok=True)
                    continue
                if not fp.is_file():
                    continue
                relname = str(fp.relative_to(d))
                rel = f"{rel0}!/{relname}"
                if not self._count_ok(rel):
                    return
                sz = fp.stat().st_size
                if self.total + sz > config.MAX_UNPACK_TOTAL_BYTES:
                    self._over_budget(rel)
                    return
                self.total += sz
                self._register(fp, rel, item["depth"] + 1, rel0, None)


class _Corrupt(Exception):
    pass


class _Bounded:
    """Read at most `left` bytes from an already positioned file object."""

    def __init__(self, f, left):
        self.f, self.left = f, left

    def read(self, n=-1):
        if self.left <= 0:
            return b""
        n = self.left if n is None or n < 0 else min(n, self.left)
        b = self.f.read(n)
        self.left -= len(b)
        return b


def _ar_members(path):
    """Yield (name, data_offset, size) for every regular member of a System V / GNU / BSD ar archive.
    Symbol tables ("/", "/SYM64/", "__.SYMDEF") are skipped; GNU "//" long names and BSD "#1/N" are resolved."""
    size_total = os.path.getsize(path)
    longnames = b""
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError("bad ar magic")
        pos = 8
        while pos < size_total:
            if pos % 2:
                pos += 1
                if pos >= size_total:
                    break
            f.seek(pos)
            hdr = f.read(60)
            if len(hdr) < 60:
                if hdr.strip(b"\n") == b"":
                    break
                raise ValueError("truncated ar header")
            if hdr[58:60] != b"`\n":
                raise ValueError("bad ar header terminator")
            raw = hdr[:16].decode("latin-1").rstrip(" ")
            try:
                size = int(hdr[48:58].decode("ascii").strip() or "0")
            except ValueError:
                raise ValueError("bad ar member size")
            if size < 0 or pos + 60 + size > size_total:
                raise ValueError("ar member exceeds file size")
            data_off = pos + 60
            pos = data_off + size
            if raw in ("/", "/SYM64/") or raw.startswith("__.SYMDEF"):
                continue
            if raw == "//":
                f.seek(data_off)
                longnames = f.read(size)
                continue
            if raw.startswith("#1/"):
                nlen = int(raw[3:] or "0")
                if nlen < 0 or nlen > size:
                    raise ValueError("bad BSD ar name length")
                f.seek(data_off)
                name = f.read(nlen).rstrip(b"\0").decode("utf-8", "replace")
                data_off += nlen
                size -= nlen
            elif raw.startswith("/") and raw[1:].isdigit():
                off = int(raw[1:])
                end = longnames.find(b"/\n", off)
                name = longnames[off: end if end >= 0 else None].decode("utf-8", "replace")
            else:
                name = raw[:-1] if raw.endswith("/") else raw
            yield name or "unnamed", data_off, size


def zlib_error():
    import zlib
    return zlib.error


def _link_escapes(name, target, hard=False):
    """True if a symlink/hardlink target resolves outside the archive root."""
    import posixpath
    t = target.replace("\\", "/")
    if t.startswith("/") or re.match(r"^[A-Za-z]:", t):
        return True
    base = "" if hard else posixpath.dirname(name.replace("\\", "/"))
    norm = posixpath.normpath(posixpath.join("/__root__", base, t))
    return not (norm == "/__root__" or norm.startswith("/__root__/"))
