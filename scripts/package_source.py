"""Deterministic allowlisted source packaging. No network, Git credentials or deployment."""
import argparse,gzip,hashlib,io,json,re,stat,tarfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]
SAMPLE='deploy/agentcrashlab.env.example'
DOTFILE='.gitignore'
MAX_FILE=1_000_000
CREDENTIAL = re.compile(
    r"""(?im)^[ \t]*["']?(?:VULTR(?:_INFERENCE)?_API_KEY|ELEVENLABS_API_KEY|OPENAI_API_KEY|"""
    r"""AGENTCRASHLAB_TOKEN|API_KEY|ACCESS_TOKEN|CLIENT_SECRET|PASSWORD|SECRET_KEY)["']?[ \t]*[=:][ \t]*"""
    r"""([^\r\n]*)"""
)
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "provider_token": re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{25,}|"
                                 r"github_pat_[A-Za-z0-9_]{25,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{12,})\b"),
    "credential_url": re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:@]+:[^\s/@]+@"),
    "bearer_literal": re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9_.=-]{20,}\b"),
    "private_path": re.compile(r"/Users/[A-Za-z0-9._-]+/|\b(?:libfile_|file_)[0-9a-f]{24,}\b"),
}


class ReviewError(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_path(name):
    if name == DOTFILE:
        return
    parts = PurePosixPath(name).parts
    if (not parts or name != "/".join(parts) or not re.fullmatch(r"[A-Za-z0-9_./-]+", name)
            or any(part in (".", "..", "node_modules", "dist", "__pycache__") or part.startswith(".") for part in parts)
            or (".env" in name and name != SAMPLE)
            or name.endswith((".db", ".sqlite", ".sqlite3", ".pem", ".key", ".log", ".mp4"))):
        raise ReviewError("Unsafe archive path")


def scan(name, data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{name}: non_utf8"]
    hits = []
    for kind, pattern in PATTERNS.items():
        matches = pattern.finditer(text)
        if kind == "bearer_literal" and name == "tests/test_lab.py":
            # These two literal values are deliberately fake and used only in mocked tests.
            fake = {"synthetic-local-test-token", "synthetic-mocked-only"}
            matches = (match for match in matches if match.group().split()[-1] not in fake)
        if next(matches, None):
            hits.append(kind)
    if any(match.group(1).strip().rstrip(",").strip().strip("\"'") for match in CREDENTIAL.finditer(text)):
        hits.append("credential_literal")
    if "\0" in text:
        hits.append("binary_content")
    return [f"{name}: {category}" for category in hits]



def collect(root=ROOT):
    names=json.loads((root/'RELEASE_ALLOWLIST.json').read_text())
    if not isinstance(names,list) or names!=sorted(set(names)):
        raise ReviewError('Invalid explicit allowlist')
    files={}
    for name in names:
        check_path(name)
        if any(word in name.lower() for word in ('approval','private','state/','audit.sqlite','session')):
            raise ReviewError('Private record path')
        path=root
        for part in PurePosixPath(name).parts:
            path/=part
            if path.is_symlink():raise ReviewError(name+': symlink')
        st=path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size>MAX_FILE:raise ReviewError(name+': invalid file')
        data=path.read_bytes()
        hits=scan(name,data)
        if hits:raise ReviewError('Scan rejected: '+', '.join(hits))
        files[name]=data
    return files


def manifest(files):
    return {'schema_version':1,'files':{k:sha(v) for k,v in sorted(files.items())}}


def encode(files):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(files.items()):
            check_path(name);info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
            archive.addfile(info,io.BytesIO(data))
    out=io.BytesIO()
    with gzip.GzipFile(fileobj=out,mode='wb',filename='',mtime=0) as stream:stream.write(raw.getvalue())
    return out.getvalue()


def verify_archive(data,files):
    if len(data)>8_000_000:raise ReviewError('Archive too large')
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:raw=stream.read(8_000_001)
    if len(raw)>8_000_000:raise ReviewError('Expanded archive too large')
    observed={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for info in archive:
            check_path(info.name)
            if info.name not in files or info.name in observed or info.type!=tarfile.REGTYPE or info.size>MAX_FILE:
                raise ReviewError('Unexpected member/path/type')
            observed[info.name]=archive.extractfile(info).read()
    if observed!=files or encode(observed)!=data:raise ReviewError('Archive differs from reviewed bytes')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);args=parser.parse_args()
    files=collect();expected=manifest(files)
    if expected!=json.loads((ROOT/'SOURCE_MANIFEST.json').read_text()):raise ReviewError('Source manifest mismatch')
    payload={**files,'SOURCE_MANIFEST.json':(ROOT/'SOURCE_MANIFEST.json').read_bytes()}
    data=encode(payload);verify_archive(data,payload)
    if args.output:
        with args.output.open('xb') as stream:stream.write(data)
    print(json.dumps({'files':len(payload),'archive_bytes':len(data),'archive_sha256':sha(data),'scan':'passed filenames/categories only'}))
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,ReviewError):raise SystemExit('Source review failed; inspect safe filename/category diagnostics locally') from None
