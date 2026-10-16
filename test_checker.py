"""checker.py 함수 테스트 (pytest 스타일)

파일 하나가 검사되는 순서대로 묶었다.
출력 정제 → 해시 계산 → 폴더 훑기 → 비밀키·서명 → 스냅샷 만들기 → 비교 → 검증

프로그램을 실제로 실행해 확인하는 테스트(종료 코드, 특수 파일 등)는 test_cli.py 에 있다.
"""

import json
import os
import stat
from pathlib import Path


import checker


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
    hashes, errors = checker.collect_hashes(str(tmp_path))
    assert "a.txt" in hashes
    assert errors == {}


def test_하위_폴더의_파일까지_찾는다(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "top.txt").write_text("위")
    (tmp_path / "sub" / "inner.txt").write_text("아래")

    hashes, _ = checker.collect_hashes(str(tmp_path))

    # 경로 구분자는 운영체제마다 다르므로 비교 전에 통일한다
    found = {Path(key).as_posix() for key in hashes}
    assert "top.txt" in found
    assert "sub/inner.txt" in found


def test_빈_폴더는_빈_결과를_돌려준다(tmp_path):
    assert checker.collect_hashes(str(tmp_path)) == ({}, {})


def test_읽을_수_없는_파일은_오류로_기록된다(tmp_path):
    blocked = tmp_path / "blocked.txt"
    blocked.write_text("비밀")
    blocked.chmod(0o000)
    try:
        hashes, errors = checker.collect_hashes(str(tmp_path))
        assert "blocked.txt" not in hashes
        assert "blocked.txt" in errors
    finally:
        blocked.chmod(0o644)


def test_읽을_수_없는_하위_폴더는_검사_실패로_기록된다(tmp_path):
    docs = make_docs(tmp_path, {"top.txt": "위", "sub/a.txt": "아래"})
    (docs / "sub").chmod(0o000)
    try:
        hashes, errors = checker.collect_hashes(str(docs))
        assert "sub" in errors, "열지 못한 폴더가 조용히 건너뛰어졌다"
    finally:
        (docs / "sub").chmod(0o755)


def test_숨김_폴더의_파일도_검사한다(tmp_path):
    hidden = tmp_path / ".config"
    hidden.mkdir()
    (hidden / "credentials.txt").write_text("비밀 정보")

    hashes, _ = checker.collect_hashes(str(tmp_path))

    assert ".config/credentials.txt" in {Path(k).as_posix() for k in hashes}


def test_exclude로_지정한_폴더만_건너뛴다(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("깃 내부")
    (tmp_path / "real.txt").write_text("진짜")

    hashes, _ = checker.collect_hashes(str(tmp_path), exclude_dirs={".git"})

    assert list(hashes.keys()) == ["real.txt"]


def test_하위_폴더의_동일_이름_파일은_검사한다(tmp_path):
    # 사용자가 보관하는 backup/snapshot.json 은 도구가 만든 것이 아니므로 검사해야 한다
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / checker.SNAPSHOT_FILE).write_text("사용자 데이터")

    hashes, _ = checker.collect_hashes(str(tmp_path))

    assert f"backup/{checker.SNAPSHOT_FILE}" in {Path(k).as_posix() for k in hashes}


def test_도구가_만든_파일은_경로로_판단해_제외한다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / checker.SNAPSHOT_FILE).write_text("{}")
    (tmp_path / checker.LOG_FILE).write_text("로그")
    (tmp_path / checker.KEY_FILE).write_text("키")
    (tmp_path / "user.txt").write_text("사용자")

    hashes, _ = checker.collect_hashes(str(tmp_path))

    assert list(hashes.keys()) == ["user.txt"]


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


def test_키_파일이_없으면_만든다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not os.path.exists(checker.KEY_FILE)

    key = checker.load_or_create_key()

    assert os.path.exists(checker.KEY_FILE)
    assert len(key) >= 32


def test_다시_불러오면_같은_키를_돌려준다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert checker.load_or_create_key() == checker.load_or_create_key()


def test_키_파일은_소유자만_읽을_수_있다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    checker.load_or_create_key()

    mode = stat.S_IMODE(os.stat(checker.KEY_FILE).st_mode)

    assert mode == 0o600, f"키 파일 권한이 {oct(mode)} 이라 다른 사용자가 읽을 수 있다"


# ─────────────────────────────────────────
# 5. create_snapshot: 기준선 만들기
# ─────────────────────────────────────────

def test_스냅샷에_서명이_들어간다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"doc1.txt": "원본 내용"})

    checker.create_snapshot("./docs")

    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    assert "signature" in data
    assert data["signature"] == checker.compute_signature(data, checker.load_or_create_key())


def test_읽기_실패가_있으면_스냅샷을_만들지_않는다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"blocked.txt": "비밀"})
    (docs / "blocked.txt").chmod(0o000)
    try:
        code = checker.create_snapshot("./docs")
        assert code == checker.EXIT_SCAN_INCOMPLETE
        assert not (tmp_path / checker.SNAPSHOT_FILE).exists(), \
            "불완전한 스캔으로 기준선을 만들면 이후 검증을 신뢰할 수 없다"
    finally:
        (docs / "blocked.txt").chmod(0o644)


def test_스냅샷_저장이_중간에_실패해도_기존_기준선은_남는다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})
    checker.create_snapshot("./docs")
    original = (tmp_path / checker.SNAPSHOT_FILE).read_text()

    def disk_full(*args, **kwargs):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(checker.json, "dump", disk_full)

    code = checker.create_snapshot("./docs")

    assert code != checker.EXIT_OK
    assert (tmp_path / checker.SNAPSHOT_FILE).read_text() == original


# ─────────────────────────────────────────
# 6. compare: 비교 로직만 따로 (파일 없이 사전만으로)
# ─────────────────────────────────────────

def test_변조_삭제_추가를_구분한다():
    old = {"a.txt": "h1", "b.txt": "h2", "c.txt": "h3"}
    new = {"a.txt": "h1", "b.txt": "바뀜", "d.txt": "h4"}

    result = checker.compare(old, new, scan_errors={})

    assert result.modified == ["b.txt"]
    assert result.deleted == ["c.txt"]
    assert result.added == ["d.txt"]
    assert result.change_count == 3


def test_바뀐_것이_없으면_변경_0건():
    same = {"a.txt": "h1"}
    result = checker.compare(same, dict(same), scan_errors={})
    assert result.change_count == 0
    assert result.exit_code() == checker.EXIT_OK


def test_읽지_못한_파일은_삭제로_세지_않는다():
    result = checker.compare({"a.txt": "h1"}, {}, scan_errors={"a.txt": "Permission denied"})
    assert result.deleted == []
    assert result.unverifiable == {"a.txt": "Permission denied"}


def test_읽지_못한_폴더_안의_파일도_삭제로_세지_않는다():
    old = {os.path.join("sub", "c.txt"): "h1", "a.txt": "h2"}
    result = checker.compare(old, {"a.txt": "h2"}, scan_errors={"sub": "Permission denied"})
    assert result.deleted == []


def test_검사하지_못한_항목이_있으면_변경이_있어도_종료코드_4():
    result = checker.compare({"a.txt": "h1", "b.txt": "h2"}, {"a.txt": "바뀜"},
                             scan_errors={"b.txt": "Permission denied"})
    assert result.modified == ["a.txt"]
    assert result.exit_code() == checker.EXIT_SCAN_INCOMPLETE


def test_변경이_있으면_종료코드_1():
    result = checker.compare({"a.txt": "h1"}, {"a.txt": "바뀜"}, scan_errors={})
    assert result.exit_code() == checker.EXIT_CHANGES_DETECTED


# ─────────────────────────────────────────
# 7. verify_integrity: 검증과 보고서
# ─────────────────────────────────────────

def test_변경이_없으면_무결성_확인_메시지를_낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"doc1.txt": "원본"})

    checker.create_snapshot("./docs")
    checker.verify_integrity("./docs")

    assert "모든 파일의 무결성이 확인되었습니다" in capsys.readouterr().out


def test_파일_내용이_바뀌면_변조로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"doc1.txt": "원본"})

    checker.create_snapshot("./docs")
    (docs / "doc1.txt").write_text("몰래 바꾼 내용")
    checker.verify_integrity("./docs")

    output = capsys.readouterr().out
    assert "변조된 파일 (1개)" in output
    assert "doc1.txt" in output


def test_파일이_사라지면_삭제로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"doc1.txt": "원본"})

    checker.create_snapshot("./docs")
    (docs / "doc1.txt").unlink()
    checker.verify_integrity("./docs")

    assert "삭제된 파일 (1개)" in capsys.readouterr().out


def test_없던_파일이_생기면_추가로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"doc1.txt": "원본"})

    checker.create_snapshot("./docs")
    (docs / "backdoor.txt").write_text("해킹 흔적")
    checker.verify_integrity("./docs")

    output = capsys.readouterr().out
    assert "새로 추가된 파일 (1개)" in output
    assert "backdoor.txt" in output


def test_읽기_실패_파일이_삭제로_표시되지_않는다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"ok.txt": "정상", "blocked.txt": "비밀"})

    checker.create_snapshot("./docs")
    (docs / "blocked.txt").chmod(0o000)
    try:
        code = checker.verify_integrity("./docs")
        output = capsys.readouterr().out
        assert "삭제된 파일 (1개)" not in output, "읽기 실패를 삭제로 오판함"
        assert "검사하지 못한 파일" in output
        assert code == checker.EXIT_SCAN_INCOMPLETE
    finally:
        (docs / "blocked.txt").chmod(0o644)


def test_형식이_잘못된_스냅샷은_크래시_없이_검증_실패(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"doc1.txt": "원본"})
    (tmp_path / checker.SNAPSHOT_FILE).write_text("{}")  # 유효한 JSON 이지만 스냅샷 형식이 아님

    assert checker.verify_integrity("./docs") == checker.EXIT_VERIFICATION_FAILED


def test_키가_없으면_검증을_중단하고_성공을_말하지_않는다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})

    checker.create_snapshot("./docs")
    (tmp_path / checker.KEY_FILE).unlink()

    code = checker.verify_integrity("./docs")
    output = capsys.readouterr().out

    assert "무결성이 확인되었습니다" not in output, "검증 불가 상태에서 성공을 단언함"
    assert code == checker.EXIT_VERIFICATION_FAILED


def test_서명이_없는_스냅샷은_검증을_중단한다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})

    checker.create_snapshot("./docs")
    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    del data["signature"]
    (tmp_path / checker.SNAPSHOT_FILE).write_text(json.dumps(data))

    code = checker.verify_integrity("./docs")

    assert "무결성이 확인되었습니다" not in capsys.readouterr().out
    assert code == checker.EXIT_VERIFICATION_FAILED


def test_allow_unsigned_옵션을_주면_서명_없이도_검증한다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})

    checker.create_snapshot("./docs")
    (tmp_path / checker.KEY_FILE).unlink()

    code = checker.verify_integrity("./docs", allow_unsigned=True)

    assert code == checker.EXIT_OK
    assert "무결성이 확인되었습니다" in capsys.readouterr().out


# ─────────────────────────────────────────
# 8. --key-file: 비밀키를 스냅샷과 다른 곳에 두기
# ─────────────────────────────────────────

def test_지정한_경로에_키를_만든다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    vault = tmp_path / "vault"
    vault.mkdir()
    key_path = vault / "integrity.key"

    checker.load_or_create_key(str(key_path))

    assert key_path.exists()
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600
    assert not (tmp_path / checker.KEY_FILE).exists(), "기본 위치에도 키를 만들었다"


def test_지정한_키로_서명하고_같은_키로_검증한다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_docs(tmp_path, {"a.txt": "내용"})
    (tmp_path / "vault").mkdir()
    key_path = str(tmp_path / "vault" / "integrity.key")

    checker.create_snapshot("./docs", key_file=key_path)

    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    assert data["signature"] == checker.compute_signature(data, checker.load_or_create_key(key_path))
    assert checker.verify_integrity("./docs", key_file=key_path) == checker.EXIT_OK


def test_검사_폴더_안에_둔_키_파일은_검사에서_뺀다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    key_path = docs / "my.key"
    key_path.write_text("키")

    hashes, _ = checker.collect_hashes(str(docs), key_file=str(key_path))

    assert list(hashes.keys()) == ["a.txt"]
