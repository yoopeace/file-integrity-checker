"""checker.py 함수 테스트 (pytest 스타일)

파일 하나가 검사되는 순서대로 묶었다.
출력 정제 → 해시 계산 → 폴더 훑기 → 비밀키·서명 → 스냅샷 만들기 → 비교 → 검증

프로그램을 실제로 실행해 확인하는 테스트(종료 코드, 특수 파일 등)는 test_cli.py 에 있다.
"""

import json
import os
import re
import stat
from pathlib import Path

import pytest

import checker


def tool_files_in(tmp_path, key=None):
    """테스트용 임시 폴더에 도구 파일(스냅샷·로그·비밀키) 위치를 정한다."""
    return checker.ToolFiles(
        snapshot=str(tmp_path / checker.SNAPSHOT_FILE),
        log=str(tmp_path / checker.LOG_FILE),
        key=key or str(tmp_path / checker.KEY_FILE),
    )


def make_docs(tmp_path, files):
    """tmp_path/docs 아래에 {경로: 내용} 대로 파일을 만든다."""
    docs = tmp_path / "docs"
    docs.mkdir()
    for name, content in files.items():
        path = docs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return docs


# ─────────────────────────────────────────
# 1. safe_path: 파일명을 화면에 찍기 전 정제
# ─────────────────────────────────────────

def test_파일명의_제어문자는_출력_전에_제거된다():
    assert checker.safe_path("a\x1b[31mb\x07c") == "abc"
    assert checker.safe_path("normal.txt") == "normal.txt"


def test_8비트_제어문자와_방향_전환_문자도_제거된다():
    # U+202E 는 글자 방향을 뒤집어 'invoice\u202etxt.exe' 를 'invoiceexe.txt' 처럼 보이게 한다
    assert checker.safe_path("invoice\u202etxt.exe") == "invoicetxt.exe"
    # \x9b 는 일부 터미널에서 ESC[ 와 같은 효과를 낸다
    assert checker.safe_path("a\x9b31mb") == "a31mb"


# ─────────────────────────────────────────
# 2. calculate_hash: 파일 하나의 지문 만들기
# ─────────────────────────────────────────

def test_알려진_SHA256_값과_일치한다(tmp_path):
    target = tmp_path / "hello.txt"
    target.write_bytes(b"hello")
    expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert checker.calculate_hash(str(target)) == expected


def test_내용이_같으면_해시도_같다(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("같은 내용")
    b.write_text("같은 내용")
    assert checker.calculate_hash(str(a)) == checker.calculate_hash(str(b))


def test_한_글자만_달라도_해시가_완전히_바뀐다(tmp_path):
    target = tmp_path / "doc.txt"
    target.write_text("계약 금액: 50억원")
    before = checker.calculate_hash(str(target))

    target.write_text("계약 금액: 5억원")
    after = checker.calculate_hash(str(target))

    assert before != after


def test_빈_파일도_해시를_만든다(tmp_path):
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")
    assert len(checker.calculate_hash(str(target))) == 64


# ─────────────────────────────────────────
# 3. collect_hashes: 폴더 전체 훑기
# ─────────────────────────────────────────

def test_해시와_오류를_함께_돌려준다(tmp_path):
    (tmp_path / "a.txt").write_text("내용")
    scan = checker.collect_hashes(str(tmp_path))
    assert "a.txt" in scan.hashes
    assert scan.errors == {}


def test_하위_폴더의_파일까지_찾는다(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "top.txt").write_text("위")
    (tmp_path / "sub" / "inner.txt").write_text("아래")

    hashes = checker.collect_hashes(str(tmp_path)).hashes

    # 경로 구분자는 운영체제마다 다르므로 비교 전에 통일한다
    found = {Path(key).as_posix() for key in hashes}
    assert "top.txt" in found
    assert "sub/inner.txt" in found


def test_빈_폴더는_빈_결과를_돌려준다(tmp_path):
    assert checker.collect_hashes(str(tmp_path)) == checker.Scan({}, {})


def test_읽을_수_없는_파일은_오류로_기록된다(tmp_path):
    blocked = tmp_path / "blocked.txt"
    blocked.write_text("비밀")
    blocked.chmod(0o000)
    try:
        scan = checker.collect_hashes(str(tmp_path))
        assert "blocked.txt" not in scan.hashes
        assert "blocked.txt" in scan.errors
    finally:
        blocked.chmod(0o644)


def test_읽을_수_없는_하위_폴더는_검사_실패로_기록된다(tmp_path):
    docs = make_docs(tmp_path, {"top.txt": "위", "sub/a.txt": "아래"})
    (docs / "sub").chmod(0o000)
    try:
        scan = checker.collect_hashes(str(docs))
        assert "sub" in scan.errors, "열지 못한 폴더가 조용히 건너뛰어졌다"
    finally:
        (docs / "sub").chmod(0o755)


def test_숨김_폴더의_파일도_검사한다(tmp_path):
    hidden = tmp_path / ".config"
    hidden.mkdir()
    (hidden / "credentials.txt").write_text("비밀 정보")

    hashes = checker.collect_hashes(str(tmp_path)).hashes

    assert ".config/credentials.txt" in {Path(k).as_posix() for k in hashes}


def test_exclude로_지정한_폴더만_건너뛴다(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("깃 내부")
    (tmp_path / "real.txt").write_text("진짜")

    hashes = checker.collect_hashes(str(tmp_path), exclude_dirs={".git"}).hashes

    assert list(hashes.keys()) == ["real.txt"]


def test_하위_폴더의_동일_이름_파일은_검사한다(tmp_path):
    # 사용자가 보관하는 backup/snapshot.json 은 도구가 만든 것이 아니므로 검사해야 한다
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / checker.SNAPSHOT_FILE).write_text("사용자 데이터")

    hashes = checker.collect_hashes(str(tmp_path)).hashes

    assert f"backup/{checker.SNAPSHOT_FILE}" in {Path(k).as_posix() for k in hashes}


def test_도구가_만든_파일은_경로로_판단해_제외한다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / checker.SNAPSHOT_FILE).write_text("{}")
    (tmp_path / checker.LOG_FILE).write_text("로그")
    (tmp_path / checker.KEY_FILE).write_text("키")
    (tmp_path / "user.txt").write_text("사용자")

    hashes = checker.collect_hashes(str(tmp_path)).hashes

    assert list(hashes.keys()) == ["user.txt"]


# ─────────────────────────────────────────
# 3-1. Scan: 스캔 결과가 '검사 불가' 여부를 스스로 답한다
# ─────────────────────────────────────────

def test_읽지_못한_파일_자신은_검사_불가다():
    scan = checker.Scan({}, {"a.txt": "Permission denied"})
    assert scan.is_unverifiable("a.txt")
    assert not scan.is_unverifiable("b.txt")


def test_읽지_못한_폴더_안의_경로는_모두_검사_불가다():
    scan = checker.Scan({}, {"sub": "Permission denied"})
    assert scan.is_unverifiable(os.path.join("sub", "c.txt"))
    assert scan.is_unverifiable(os.path.join("sub", "deep", "d.txt"))


def test_이름만_비슷한_폴더는_검사_불가로_보지_않는다():
    # 'sub' 를 못 읽었다고 'subway' 안의 파일까지 판정을 포기하면 안 된다
    scan = checker.Scan({}, {"sub": "Permission denied"})
    assert not scan.is_unverifiable(os.path.join("subway", "a.txt"))
    assert not scan.is_unverifiable("sub.txt")


def test_검사_폴더_자체를_못_읽으면_모든_경로가_검사_불가다():
    # 검사 폴더 자체를 열지 못하면 실패 목록에 '.' 으로 기록된다
    scan = checker.Scan({}, {".": "Permission denied"})
    assert scan.is_unverifiable("a.txt")
    assert scan.is_unverifiable(os.path.join("sub", "c.txt"))


def test_검사_폴더_자체를_못_열면_점으로_기록된다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    docs.chmod(0o000)
    try:
        scan = checker.collect_hashes(str(docs))
    finally:
        docs.chmod(0o755)
    assert list(scan.errors) == ["."]
    assert scan.is_unverifiable("a.txt")


# ─────────────────────────────────────────
# 4. 비밀키와 스냅샷 서명
# ─────────────────────────────────────────

SAMPLE_SNAPSHOT = {
    "created_at": "2026-01-01T10:00:00",
    "target_directory": "/tmp/docs",
    "file_count": 1,
    "files": {"doc1.txt": "abc123"},
}
SAMPLE_KEY = "0" * 64


def test_같은_데이터와_키는_같은_서명():
    assert (checker.compute_signature(SAMPLE_SNAPSHOT, SAMPLE_KEY)
            == checker.compute_signature(SAMPLE_SNAPSHOT, SAMPLE_KEY))


def test_해시가_바뀌면_서명이_달라진다():
    tampered = json.loads(json.dumps(SAMPLE_SNAPSHOT))
    tampered["files"]["doc1.txt"] = "변조된해시"
    assert (checker.compute_signature(SAMPLE_SNAPSHOT, SAMPLE_KEY)
            != checker.compute_signature(tampered, SAMPLE_KEY))


def test_키가_다르면_서명이_달라진다():
    assert (checker.compute_signature(SAMPLE_SNAPSHOT, SAMPLE_KEY)
            != checker.compute_signature(SAMPLE_SNAPSHOT, "1" * 64))


def test_signature_항목_자체는_서명_계산에서_제외한다():
    signed = dict(SAMPLE_SNAPSHOT, signature="이미 들어있는 서명")
    assert (checker.compute_signature(SAMPLE_SNAPSHOT, SAMPLE_KEY)
            == checker.compute_signature(signed, SAMPLE_KEY))


def test_서명용_키가_없으면_만들고_만들었다고_알린다(tmp_path):
    key_path = tmp_path / "integrity.key"

    key, created = checker.key_for_signing(str(key_path))

    assert key_path.exists()
    assert created is True
    assert len(key) >= 32


def test_서명용_키가_있으면_그대로_쓰고_새로_만들지_않는다(tmp_path):
    key_path = str(tmp_path / "integrity.key")
    first, _ = checker.key_for_signing(key_path)

    second, created = checker.key_for_signing(key_path)

    assert second == first
    assert created is False


def test_키_파일은_소유자만_읽을_수_있다(tmp_path):
    key_path = tmp_path / "integrity.key"
    checker.key_for_signing(str(key_path))

    mode = stat.S_IMODE(os.stat(key_path).st_mode)

    assert mode == 0o600, f"키 파일 권한이 {oct(mode)} 이라 다른 사용자가 읽을 수 있다"


def test_빈_키_파일로는_서명하지_않는다(tmp_path):
    # 빈 키로 서명하면 누구나 같은 서명을 만들 수 있다
    key_path = tmp_path / "integrity.key"
    key_path.write_text("")

    with pytest.raises(checker.KeyUnavailable):
        checker.key_for_signing(str(key_path))


def test_키를_만들_수_없는_경로면_서명하지_않는다(tmp_path):
    # USB 가 꽂혀 있지 않은 경우처럼 폴더가 없는 경로
    with pytest.raises(checker.KeyUnavailable):
        checker.key_for_signing(str(tmp_path / "no_usb" / "integrity.key"))


def test_검증용_키는_서명용으로_만든_키와_같다(tmp_path):
    key_path = str(tmp_path / "integrity.key")
    key, _ = checker.key_for_signing(key_path)

    assert checker.key_for_verifying(key_path) == key


def test_검증용_키가_없으면_만들지_않고_없다고_알린다(tmp_path):
    # 검증 쪽이 키를 새로 만들면, 엉뚱한 새 키로 서명을 확인하게 된다
    key_path = tmp_path / "integrity.key"

    with pytest.raises(checker.KeyUnavailable) as exc:
        checker.key_for_verifying(str(key_path))

    assert exc.value.missing is True
    assert not key_path.exists(), "검증 쪽이 키를 새로 만들었다"


def test_빈_검증용_키는_쓸_수_없다(tmp_path):
    key_path = tmp_path / "integrity.key"
    key_path.write_text("")

    with pytest.raises(checker.KeyUnavailable) as exc:
        checker.key_for_verifying(str(key_path))

    assert exc.value.missing is False


def test_읽을_수_없는_검증용_키는_쓸_수_없다(tmp_path):
    key_path = tmp_path / "integrity.key"
    key_path.write_text("a" * 64)
    key_path.chmod(0o000)
    try:
        with pytest.raises(checker.KeyUnavailable) as exc:
            checker.key_for_verifying(str(key_path))
        assert exc.value.missing is False
    finally:
        key_path.chmod(0o600)


# ─────────────────────────────────────────
# 5. create_snapshot: 기준선 만들기
# ─────────────────────────────────────────

def test_스냅샷에_서명이_들어간다(tmp_path):
    tf = tool_files_in(tmp_path)
    make_docs(tmp_path, {"doc1.txt": "원본 내용"})

    checker.create_snapshot(str(tmp_path / "docs"), tool_files=tf)

    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    assert "signature" in data
    assert data["signature"] == checker.compute_signature(data, checker.key_for_verifying(tf.key))


def test_읽기_실패가_있으면_스냅샷을_만들지_않는다(tmp_path):
    tf = tool_files_in(tmp_path)
    docs = make_docs(tmp_path, {"blocked.txt": "비밀"})
    (docs / "blocked.txt").chmod(0o000)
    try:
        code = checker.create_snapshot(str(tmp_path / "docs"), tool_files=tf)
        assert code == checker.EXIT_SCAN_INCOMPLETE
        assert not (tmp_path / checker.SNAPSHOT_FILE).exists(), \
            "불완전한 스캔으로 기준선을 만들면 이후 검증을 신뢰할 수 없다"
    finally:
        (docs / "blocked.txt").chmod(0o644)


def test_빈_키_파일로는_스냅샷을_만들지_않는다(tmp_path):
    tf = tool_files_in(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})
    (tmp_path / checker.KEY_FILE).write_text("")

    code = checker.create_snapshot(str(tmp_path / "docs"), tool_files=tf)

    assert code == checker.EXIT_VERIFICATION_FAILED
    assert not (tmp_path / checker.SNAPSHOT_FILE).exists()


def test_스냅샷_저장이_중간에_실패해도_기존_기준선은_남는다(tmp_path, monkeypatch):
    tf = tool_files_in(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})
    checker.create_snapshot(str(tmp_path / "docs"), tool_files=tf)
    original = (tmp_path / checker.SNAPSHOT_FILE).read_text()

    def disk_full(*args, **kwargs):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(checker.json, "dump", disk_full)

    code = checker.create_snapshot(str(tmp_path / "docs"), tool_files=tf)

    assert code != checker.EXIT_OK
    assert (tmp_path / checker.SNAPSHOT_FILE).read_text() == original


# ─────────────────────────────────────────
# 6. compare: 비교 로직만 따로 (파일 없이 사전만으로)
# ─────────────────────────────────────────

def test_변조_삭제_추가를_구분한다():
    old = {"a.txt": "h1", "b.txt": "h2", "c.txt": "h3"}
    new = {"a.txt": "h1", "b.txt": "바뀜", "d.txt": "h4"}

    result = checker.compare(old, checker.Scan(new, {}))

    assert result.modified == ["b.txt"]
    assert result.deleted == ["c.txt"]
    assert result.added == ["d.txt"]
    assert result.change_count == 3


def test_바뀐_것이_없으면_변경_0건():
    same = {"a.txt": "h1"}
    result = checker.compare(same, checker.Scan(dict(same), {}))
    assert result.change_count == 0
    assert result.exit_code() == checker.EXIT_OK


def test_읽지_못한_파일은_삭제로_세지_않는다():
    result = checker.compare({"a.txt": "h1"}, checker.Scan({}, {"a.txt": "Permission denied"}))
    assert result.deleted == []
    assert result.unverifiable == {"a.txt": "Permission denied"}


def test_읽지_못한_폴더_안의_파일도_삭제로_세지_않는다():
    old = {os.path.join("sub", "c.txt"): "h1", "a.txt": "h2"}
    result = checker.compare(old, checker.Scan({"a.txt": "h2"}, {"sub": "Permission denied"}))
    assert result.deleted == []


def test_검사하지_못한_항목이_있으면_변경이_있어도_종료코드_4():
    result = checker.compare({"a.txt": "h1", "b.txt": "h2"},
                             checker.Scan({"a.txt": "바뀜"}, {"b.txt": "Permission denied"}))
    assert result.modified == ["a.txt"]
    assert result.exit_code() == checker.EXIT_SCAN_INCOMPLETE


def test_변경이_있으면_종료코드_1():
    result = checker.compare({"a.txt": "h1"}, checker.Scan({"a.txt": "바뀜"}, {}))
    assert result.exit_code() == checker.EXIT_CHANGES_DETECTED


# ─────────────────────────────────────────
# 7. 검증: 판단은 결과 값으로 (run_verification)
# ─────────────────────────────────────────

def snapshot_docs(tmp_path, files):
    """docs 폴더를 만들고 스냅샷을 찍은 뒤 (docs 경로, ToolFiles)를 돌려준다."""
    tf = tool_files_in(tmp_path)
    docs = make_docs(tmp_path, files)
    checker.create_snapshot(str(docs), tool_files=tf)
    return docs, tf


def test_변경이_없으면_변경_0건이다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.refusal is None
    assert outcome.cautions == []
    assert outcome.comparison.change_count == 0
    assert outcome.exit_code == checker.EXIT_OK


def test_파일_내용이_바뀌면_변조로_잡아낸다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})
    (docs / "doc1.txt").write_text("몰래 바꾼 내용")

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.comparison.modified == ["doc1.txt"]
    assert outcome.exit_code == checker.EXIT_CHANGES_DETECTED


def test_파일이_사라지면_삭제로_잡아낸다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})
    (docs / "doc1.txt").unlink()

    assert checker.run_verification(str(docs), tool_files=tf).comparison.deleted == ["doc1.txt"]


def test_없던_파일이_생기면_추가로_잡아낸다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})
    (docs / "backdoor.txt").write_text("해킹 흔적")

    assert checker.run_verification(str(docs), tool_files=tf).comparison.added == ["backdoor.txt"]


def test_읽기_실패_파일은_삭제가_아니라_검사_실패다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"ok.txt": "정상", "blocked.txt": "비밀"})
    (docs / "blocked.txt").chmod(0o000)
    try:
        outcome = checker.run_verification(str(docs), tool_files=tf)
        assert outcome.comparison.deleted == [], "읽기 실패를 삭제로 오판함"
        assert "blocked.txt" in outcome.comparison.unverifiable
        assert outcome.exit_code == checker.EXIT_SCAN_INCOMPLETE
    finally:
        (docs / "blocked.txt").chmod(0o644)


def test_스냅샷이_없으면_거부하고_종료코드_2(tmp_path):
    tf = tool_files_in(tmp_path)
    docs = make_docs(tmp_path, {"a.txt": "내용"})

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.refusal.kind == "snapshot_rejected"
    assert outcome.refusal.detail.reason == "missing"
    assert outcome.exit_code == checker.EXIT_USAGE_ERROR


def test_형식이_잘못된_스냅샷은_거부하고_종료코드_3(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})
    Path(tf.snapshot).write_text("{}")  # 유효한 JSON 이지만 스냅샷 형식이 아님

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.refusal.detail.reason == "malformed"
    assert outcome.exit_code == checker.EXIT_VERIFICATION_FAILED


def test_키가_없으면_거부한다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    Path(tf.key).unlink()

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.refusal.detail.reason == "key_missing"
    assert outcome.comparison is None, "거부했는데 비교를 했다"
    assert outcome.exit_code == checker.EXIT_VERIFICATION_FAILED


def test_서명이_없는_스냅샷은_거부한다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    data = json.loads(Path(tf.snapshot).read_text())
    del data["signature"]
    Path(tf.snapshot).write_text(json.dumps(data))

    outcome = checker.run_verification(str(docs), tool_files=tf)

    assert outcome.refusal.detail.reason == "unsigned"
    assert outcome.exit_code == checker.EXIT_VERIFICATION_FAILED


def test_서명_확인을_건너뛰면_주의를_남기고_검증한다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    Path(tf.key).unlink()

    outcome = checker.run_verification(str(docs), allow_unsigned=True, tool_files=tf)

    assert outcome.refusal is None
    assert outcome.cautions == [checker.Caution("unverified", ("key_missing",))]
    assert outcome.exit_code == checker.EXIT_OK


def test_검사_폴더가_없으면_거부하고_종료코드_2(tmp_path):
    _, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})

    outcome = checker.run_verification(str(tmp_path / "no_such"), tool_files=tf)

    assert outcome.refusal.kind == "target_missing"
    assert outcome.exit_code == checker.EXIT_USAGE_ERROR


def test_제외_설정이_스냅샷과_다르면_거부하고_종료코드_2(tmp_path):
    # 검증 때만 몰래 폴더를 빼면 그 안의 변조를 숨길 수 있다
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용", ".git/payload": "원본"})

    outcome = checker.run_verification(str(docs), exclude_dirs={".git"}, tool_files=tf)

    assert outcome.refusal.kind == "exclude_mismatch"
    assert outcome.comparison is None
    assert outcome.exit_code == checker.EXIT_USAGE_ERROR


def test_다른_폴더를_검증하면_대상_폴더_불일치를_주의로_남긴다(tmp_path):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    other = tmp_path / "other"
    other.mkdir()
    (other / "a.txt").write_text("내용")

    outcome = checker.run_verification(str(other), tool_files=tf)

    assert outcome.cautions == [
        checker.Caution("target_mismatch", (os.path.abspath(docs), os.path.abspath(other)))
    ]
    assert outcome.refusal is None   # 경고만 하고 검증은 계속한다


# ─────────────────────────────────────────
# 7-1. 검증: 안전과 직결된 화면 문구 (verify_integrity)
# ─────────────────────────────────────────

def test_변경이_없으면_무결성_확인_메시지를_낸다(tmp_path, capsys):
    docs, tf = snapshot_docs(tmp_path, {"doc1.txt": "원본"})
    capsys.readouterr()

    checker.verify_integrity(str(docs), tool_files=tf)

    assert "모든 파일의 무결성이 확인되었습니다" in capsys.readouterr().out


def test_거부했을_때는_절대_무결성_확인을_말하지_않는다(tmp_path, capsys):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    Path(tf.key).unlink()
    capsys.readouterr()

    code = checker.verify_integrity(str(docs), tool_files=tf)

    assert "무결성이 확인되었습니다" not in capsys.readouterr().out, "검증 불가 상태에서 성공을 단언함"
    assert code == checker.EXIT_VERIFICATION_FAILED


def test_주의가_거부_안내보다_먼저_나온다(tmp_path, capsys):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    Path(tf.key).unlink()
    capsys.readouterr()

    checker.verify_integrity(str(docs), exclude_dirs={"cache"}, allow_unsigned=True, tool_files=tf)

    output = capsys.readouterr().out
    assert output.index("주의") < output.index("제외 설정이 스냅샷과 다릅니다")


def test_보고서의_두_시각은_같은_형식으로_초까지만_보인다(tmp_path, capsys):
    docs, tf = snapshot_docs(tmp_path, {"a.txt": "내용"})
    capsys.readouterr()

    checker.verify_integrity(str(docs), tool_files=tf)

    output = capsys.readouterr().out
    same_format = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\n"
    assert re.search(r"스냅샷 기준 시각: " + same_format, output), output
    assert re.search(r"검사 완료 시각:   " + same_format, output), output


@pytest.mark.parametrize("stored, shown", [
    ("2026-11-11T11:39:54.265421", "2026-11-11 11:39:54"),   # 지금 버전이 저장하는 형식
    ("2026-01-01T10:00:00", "2026-01-01 10:00:00"),          # 마이크로초가 없는 형식
    ("알 수 없음", "알 수 없음"),                              # 시각을 읽지 못한 경우
])
def test_스냅샷_시각을_화면_형식으로_바꾼다(stored, shown):
    assert checker.display_time(stored) == shown


def test_시각이_아닌_값은_정제해서_그대로_보인다():
    # --allow-unsigned 로 쓴 스냅샷은 created_at 이 조작됐을 수 있다
    shown = checker.display_time("\x1b[31m조작된 값")
    assert "\x1b" not in shown
    assert "조작된 값" in shown


# ─────────────────────────────────────────
# 8. --key-file: 비밀키를 스냅샷과 다른 곳에 두기
# ─────────────────────────────────────────

def test_지정한_경로에만_키를_만든다(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    key_path = vault / "integrity.key"

    checker.key_for_signing(str(key_path))

    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    created = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert created == ["vault", "vault/integrity.key"], "지정하지 않은 곳에도 파일을 만들었다"


def test_지정한_키로_서명하고_같은_키로_검증한다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    (tmp_path / "vault").mkdir()
    tf = tool_files_in(tmp_path, key=str(tmp_path / "vault" / "integrity.key"))

    checker.create_snapshot(str(docs), tool_files=tf)

    data = json.loads(Path(tf.snapshot).read_text())
    assert data["signature"] == checker.compute_signature(data, checker.key_for_verifying(tf.key))
    assert checker.verify_integrity(str(docs), tool_files=tf) == checker.EXIT_OK


def test_검사_폴더_안에_둔_키_파일은_검사에서_뺀다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    key_path = docs / "my.key"
    key_path.write_text("키")

    hashes = checker.collect_hashes(str(docs), tool_files=tool_files_in(tmp_path, key=str(key_path))).hashes

    assert list(hashes.keys()) == ["a.txt"]


# ─────────────────────────────────────────
# 9. 스냅샷 저장소: 서명해서 저장하고, 검증해서 불러오기
# ─────────────────────────────────────────

def saved_snapshot(tmp_path, files=None, exclude_dirs=()):
    """서명된 스냅샷을 저장하고 (스냅샷 경로, 키 경로)를 돌려준다."""
    snapshot_path = str(tmp_path / checker.SNAPSHOT_FILE)
    key_path = str(tmp_path / "integrity.key")
    key, _ = checker.key_for_signing(key_path)
    checker.save_snapshot(str(tmp_path / "docs"), files or {"a.txt": "h1"},
                          exclude_dirs, key, snapshot_path)
    return snapshot_path, key_path


def tamper(snapshot_path, **changes):
    """스냅샷 파일의 항목을 바꿔치기한다 (공격자 흉내)."""
    data = json.loads(Path(snapshot_path).read_text())
    data.update(changes)
    Path(snapshot_path).write_text(json.dumps(data, ensure_ascii=False))


def rejection_reason(snapshot_path, key_path, allow_unsigned=False):
    with pytest.raises(checker.SnapshotRejected) as exc:
        checker.load_snapshot(snapshot_path, key_path, allow_unsigned)
    return exc.value.reason


def test_저장한_스냅샷을_그대로_불러온다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path, {"a.txt": "h1", "b.txt": "h2"}, {"cache"})

    snapshot = checker.load_snapshot(snapshot_path, key_path)

    assert snapshot.files == {"a.txt": "h1", "b.txt": "h2"}
    assert snapshot.exclude_dirs == ["cache"]
    assert snapshot.target_directory == os.path.abspath(tmp_path / "docs")
    assert isinstance(snapshot.created_at, str)
    assert snapshot.unverified_reason is None, "신뢰할 수 있는 스냅샷이어야 한다"


def test_스냅샷이_없으면_거부한다(tmp_path):
    assert rejection_reason(str(tmp_path / "none.json"), str(tmp_path / "k")) == "missing"


def test_읽을_권한이_없는_스냅샷은_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    Path(snapshot_path).chmod(0o000)
    try:
        assert rejection_reason(snapshot_path, key_path) == "unreadable"
    finally:
        Path(snapshot_path).chmod(0o644)


def test_UTF8이_아닌_스냅샷은_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    Path(snapshot_path).write_bytes(b"\xff\xfe garbage")
    assert rejection_reason(snapshot_path, key_path) == "unreadable"


def test_깨진_JSON_스냅샷은_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    Path(snapshot_path).write_text("{oops")
    assert rejection_reason(snapshot_path, key_path) == "unreadable"


def test_스냅샷_형식이_아닌_JSON은_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    Path(snapshot_path).write_text("{}")
    assert rejection_reason(snapshot_path, key_path) == "malformed"


def test_파일_해시_값이_문자열이_아니면_형식_오류로_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    tamper(snapshot_path, files={"a.txt": 123})
    assert rejection_reason(snapshot_path, key_path) == "malformed"


def test_내용을_바꿔치기하면_서명_불일치로_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    tamper(snapshot_path, files={"a.txt": "공격자가_맞춘_해시"})
    assert rejection_reason(snapshot_path, key_path) == "signature_mismatch"


def test_서명값이_문자열이_아니면_서명_불일치로_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    tamper(snapshot_path, signature=123)
    assert rejection_reason(snapshot_path, key_path) == "signature_mismatch"


def test_서명값에_ASCII가_아닌_글자가_있어도_서명_불일치로_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    tamper(snapshot_path, signature="é")
    assert rejection_reason(snapshot_path, key_path) == "signature_mismatch"


def test_서명이_없는_스냅샷은_거부한다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    data = json.loads(Path(snapshot_path).read_text())
    del data["signature"]
    Path(snapshot_path).write_text(json.dumps(data))
    assert rejection_reason(snapshot_path, key_path) == "unsigned"


def test_키가_없으면_거부하고_키를_만들지_않는다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    os.remove(key_path)

    assert rejection_reason(snapshot_path, key_path) == "key_missing"
    assert not os.path.exists(key_path), "검증 쪽이 키를 새로 만들었다"


def test_빈_키로는_검증하지_않는다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    Path(key_path).write_text("")
    assert rejection_reason(snapshot_path, key_path) == "key_unusable"


def test_서명_확인을_건너뛰면_확인_안_된_스냅샷으로_불러온다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    os.remove(key_path)

    snapshot = checker.load_snapshot(snapshot_path, key_path, allow_unsigned=True)

    assert snapshot.unverified_reason == "key_missing"
    assert snapshot.files == {"a.txt": "h1"}


def test_서명_없는_스냅샷도_건너뛰기를_허용하면_불러온다(tmp_path):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    data = json.loads(Path(snapshot_path).read_text())
    del data["signature"]
    Path(snapshot_path).write_text(json.dumps(data))

    snapshot = checker.load_snapshot(snapshot_path, key_path, allow_unsigned=True)

    assert snapshot.unverified_reason == "unsigned"


def test_건너뛰기를_허용해도_서명_불일치는_거부한다(tmp_path):
    # '확인을 건너뛴다'와 '확인했더니 틀렸다'는 다르다
    snapshot_path, key_path = saved_snapshot(tmp_path)
    tamper(snapshot_path, files={"a.txt": "바꿔치기"})
    assert rejection_reason(snapshot_path, key_path, allow_unsigned=True) == "signature_mismatch"


def test_저장_중_실패하면_임시_파일을_남기지_않고_기존_스냅샷을_지킨다(tmp_path, monkeypatch):
    snapshot_path, key_path = saved_snapshot(tmp_path)
    original = Path(snapshot_path).read_text()

    def disk_full(*args, **kwargs):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(checker.json, "dump", disk_full)

    with pytest.raises(OSError):
        checker.save_snapshot(str(tmp_path / "docs"), {"a.txt": "새것"}, (), "k" * 64, snapshot_path)

    assert Path(snapshot_path).read_text() == original
    assert not Path(checker.snapshot_temp_path(snapshot_path)).exists()


def test_저장_중인_임시_파일은_검사에서_뺀다(tmp_path):
    tf = tool_files_in(tmp_path)
    Path(checker.snapshot_temp_path(tf.snapshot)).write_text("{}")
    (tmp_path / "user.txt").write_text("사용자")

    hashes = checker.collect_hashes(str(tmp_path), tool_files=tf).hashes

    assert list(hashes.keys()) == ["user.txt"]


# ─────────────────────────────────────────
# 10. ToolFiles: 도구 파일의 위치
# ─────────────────────────────────────────

def test_도구_파일인지_실제_위치로_판단한다(tmp_path):
    tf = tool_files_in(tmp_path)

    assert tf.includes(tf.snapshot)
    assert tf.includes(tf.log)
    assert tf.includes(tf.key)
    assert tf.includes(checker.snapshot_temp_path(tf.snapshot))
    # 같은 파일을 다른 표기로 가리켜도 같은 파일로 본다
    assert tf.includes(str(tmp_path / "sub" / ".." / checker.SNAPSHOT_FILE))
    assert not tf.includes(str(tmp_path / "user.txt"))


def test_만든_뒤에_현재_폴더가_바뀌어도_판단이_흔들리지_않는다(tmp_path, monkeypatch):
    # 비교용 실제 위치는 만들 때 한 번 확정한다
    (tmp_path / "work").mkdir()
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    tf = checker.ToolFiles()

    monkeypatch.chdir(tmp_path / "elsewhere")

    assert tf.includes(str(tmp_path / "work" / checker.SNAPSHOT_FILE))
    assert not tf.includes(str(tmp_path / "elsewhere" / checker.SNAPSHOT_FILE))


def test_기본값은_현재_폴더의_도구_파일이고_입력한_형태를_그대로_보여준다():
    tf = checker.ToolFiles()
    assert (tf.snapshot, tf.log, tf.key) == (checker.SNAPSHOT_FILE, checker.LOG_FILE, checker.KEY_FILE)
    assert checker.ToolFiles(key="./usb/k").key == "./usb/k"
