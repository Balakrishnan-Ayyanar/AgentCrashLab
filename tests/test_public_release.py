import io,json,socket,tarfile,gzip
from pathlib import Path
import pytest
from scripts import package_source as p
from scripts.reproduce_fixture import replay
from backend.judge_snapshot import Snapshot

def test_public_hosted_evidence_is_strict_and_distinct():
    s=Snapshot.model_validate_json(Path('examples/hosted-evidence.json').read_text())
    assert s.hosted_attestation.os=='ubuntu-26.10'
    assert s.hosted_attestation.host_kind=='existing_repurposed'
    hosted=[i for i in s.items if i.environment=='vultr_hosted']
    assert len(hosted)==2
    assert hosted[0].request_count==2 and hosted[0].stages[1].achieved and hosted[0].stages[3].blocked
    assert hosted[1].probe_errno=='EROFS'
    assert all(x.cleanup_verified for x in s.items)


def test_offline_fixture_has_no_model_or_containment_credit():
    x=replay()
    assert x['kind']=='offline_simulation' and not x['inference_used'] and not x['docker_used']
    assert not x['model_behavior_demonstrated'] and not x['OS_containment_demonstrated']


@pytest.mark.parametrize('name',['../escape','/absolute','.env','node_modules/x','.git/config','x.sqlite3','file.mp4'])
def test_unsafe_archive_paths_rejected(name):
    with pytest.raises(p.ReviewError):p.check_path(name)


def test_only_named_root_dotfile_is_allowed():
    p.check_path('.gitignore')
    with pytest.raises(p.ReviewError):p.check_path('nested/.gitignore')


def test_symlinks_rejected(tmp_path):
    (tmp_path/'RELEASE_ALLOWLIST.json').write_text(json.dumps(['fixture.txt']))
    (tmp_path/'fixture.txt').symlink_to('/dev/null')
    with pytest.raises(p.ReviewError):p.collect(tmp_path)


def test_secret_scan_reports_only_category():
    value='sk-'+'z'*30
    assert p.scan('fixture.txt',value.encode())==['fixture.txt: provider_token']
    assert value not in str(p.scan('fixture.txt',value.encode()))
    assert p.scan('fixture.txt',('-----BEGIN '+'PRIVATE KEY-----').encode())


def test_deterministic_archive_and_strict_members():
    files={'README.md':b'synthetic fixture\n'}
    data=p.encode(files);assert data==p.encode(files);p.verify_archive(data,files)
    with pytest.raises(p.ReviewError):p.verify_archive(data,{'other.txt':b'x'})


def test_manifest_matches_explicit_payload_and_rebuild():
    files=p.collect()
    assert p.manifest(files)==json.loads(Path('SOURCE_MANIFEST.json').read_text())
    assert all('PRIVATE' not in n and 'node_modules/' not in n for n in files)


def test_network_gate_is_active():
    with socket.socket() as sock:
        with pytest.raises(AssertionError,match='Network prohibited'):sock.connect(('192.0.2.1',443))


def test_docker_subprocess_gate_is_active():
    import subprocess
    with pytest.raises(AssertionError, match='Actual Docker prohibited'):
        subprocess.run(['docker', 'version'], check=True)
