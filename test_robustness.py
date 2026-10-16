"""오판 방지 동작 테스트 (pytest 스타일)

보안 도구에서 가장 위험한 것은 오류가 나는 것이 아니라
"정상이라고 잘못 확신하게 만드는 것"이다. 그 경우들을 고정한다.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import checker

CHECKER = str(Path(__file__).parent / "checker.py")


def run(*args, cwd):
    # timeout: 멈춤(hang) 회귀가 생겨도 테스트 전체가 영원히 멈추지 않게 한다
    return subprocess.run(
        [sys.executable, CHECKER, *args],
        cwd=cwd, capture_output=True, text=True, timeout=30,
    )


# ─────────────────────────────────────────
# 1. 읽기 실패를 '삭제'로 오판하지 않는다
# ─────────────────────────────────────────

def test_collect_hashes는_해시와_오류를_함께_돌려준다(tmp_path):
    (tmp_path / "a.txt").write_text("내용")
    hashes, errors = checker.collect_hashes(str(tmp_path))
    assert "a.txt" in hashes
    assert errors == {}


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


def test_읽기_실패_파일이_삭제로_표시되지_않는다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "ok.txt").write_text("정상")
    blocked = docs / "blocked.txt"
    blocked.write_text("비밀")

    checker.create_snapshot("./docs")
    blocked.chmod(0o000)
    try:
        code = checker.verify_integrity("./docs")
        output = capsys.readouterr().out
        assert "삭제된 파일 (1개)" not in output, "읽기 실패를 삭제로 오판함"
        assert "검사하지 못한 파일" in output
        assert code == checker.EXIT_SCAN_INCOMPLETE
    finally:
        blocked.chmod(0o644)


def test_읽기_실패가_있으면_스냅샷을_만들지_않는다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    blocked = docs / "blocked.txt"
    blocked.write_text("비밀")
    blocked.chmod(0o000)
    try:
        code = checker.create_snapshot("./docs")
        assert code == checker.EXIT_SCAN_INCOMPLETE
        assert not (tmp_path / checker.SNAPSHOT_FILE).exists(), \
            "불완전한 스캔으로 기준선을 만들면 이후 검증을 신뢰할 수 없다"
    finally:
        blocked.chmod(0o644)


# ─────────────────────────────────────────
# 2. 서명·키가 없으면 검증을 중단한다 (fail-closed)
# ─────────────────────────────────────────

def test_키가_없으면_검증을_중단하고_성공을_말하지_않는다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.txt").write_text("내용")

    checker.create_snapshot("./docs")
    (tmp_path / checker.KEY_FILE).unlink()

    code = checker.verify_integrity("./docs")
    output = capsys.readouterr().out

    assert "무결성이 확인되었습니다" not in output, "검증 불가 상태에서 성공을 단언함"
    assert code == checker.EXIT_VERIFICATION_FAILED


def test_서명이_없는_스냅샷은_검증을_중단한다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.txt").write_text("내용")

    checker.create_snapshot("./docs")
    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    del data["signature"]
    (tmp_path / checker.SNAPSHOT_FILE).write_text(json.dumps(data))

    code = checker.verify_integrity("./docs")

    assert "무결성이 확인되었습니다" not in capsys.readouterr().out
    assert code == checker.EXIT_VERIFICATION_FAILED


def test_allow_unsigned_옵션을_주면_서명_없이도_검증한다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "a.txt").write_text("내용")

    checker.create_snapshot("./docs")
    (tmp_path / checker.KEY_FILE).unlink()

    code = checker.verify_integrity("./docs", allow_unsigned=True)

    assert code == checker.EXIT_OK
    assert "무결성이 확인되었습니다" in capsys.readouterr().out


# ─────────────────────────────────────────
# 3. 검사 사각지대를 없앤다
# ─────────────────────────────────────────

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
# 4. 키 파일 권한
# ─────────────────────────────────────────

def test_키_파일은_소유자만_읽을_수_있다(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    checker.load_or_create_key()

    mode = stat.S_IMODE(os.stat(checker.KEY_FILE).st_mode)

    assert mode == 0o600, f"키 파일 권한이 {oct(mode)} 이라 다른 사용자가 읽을 수 있다"


# ─────────────────────────────────────────
# 5. 종료 코드
# ─────────────────────────────────────────

def test_변경이_없으면_종료코드_0(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("내용")
    run("--snapshot", "./docs", cwd=tmp_path)

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 0


def test_변조를_찾으면_종료코드_1(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("원본")
    run("--snapshot", "./docs", cwd=tmp_path)
    (tmp_path / "docs" / "a.txt").write_text("변조됨")

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 1


def test_옵션_없이_실행하면_종료코드_2(tmp_path):
    assert run(cwd=tmp_path).returncode == 2


def test_없는_폴더를_지정하면_종료코드_2(tmp_path):
    assert run("--snapshot", "./no_such", cwd=tmp_path).returncode == 2


def test_서명이_어긋나면_종료코드_3(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("원본")
    run("--snapshot", "./docs", cwd=tmp_path)

    # 공격자가 파일과 스냅샷 해시를 함께 조작
    (tmp_path / "docs" / "a.txt").write_text("변조됨")
    snapshot = tmp_path / checker.SNAPSHOT_FILE
    data = json.loads(snapshot.read_text())
    data["files"]["a.txt"] = checker.calculate_hash(str(tmp_path / "docs" / "a.txt"))
    snapshot.write_text(json.dumps(data))

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 3


# ─────────────────────────────────────────
# 6. 출력 정제
# ─────────────────────────────────────────

def test_파일명의_제어문자는_출력_전에_제거된다():
    assert checker.safe_path("a\x1b[31mb\x07c") == "abc"
    assert checker.safe_path("normal.txt") == "normal.txt"


def test_8비트_제어문자와_방향_전환_문자도_제거된다():
    # U+202E 는 글자 방향을 뒤집어 'invoice\u202etxt.exe' 를 'invoiceexe.txt' 처럼 보이게 한다
    assert checker.safe_path("invoice\u202etxt.exe") == "invoicetxt.exe"
    # \x9b 는 일부 터미널에서 ESC[ 와 같은 효과를 낸다
    assert checker.safe_path("a\x9b31mb") == "a31mb"


# ═════════════════════════════════════════
# 2차 검토에서 발견된 결함
# ═════════════════════════════════════════

def make_docs(tmp_path, files):
    docs = tmp_path / "docs"
    docs.mkdir()
    for name, content in files.items():
        path = docs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return docs


# ─────────────────────────────────────────
# 7. 읽을 수 없는 '폴더'도 '삭제'로 오판하지 않는다
# ─────────────────────────────────────────

def test_읽을_수_없는_하위_폴더는_검사_실패로_기록된다(tmp_path):
    docs = make_docs(tmp_path, {"top.txt": "위", "sub/a.txt": "아래"})
    (docs / "sub").chmod(0o000)
    try:
        hashes, errors = checker.collect_hashes(str(docs))
        assert "sub" in errors, "열지 못한 폴더가 조용히 건너뛰어졌다"
    finally:
        (docs / "sub").chmod(0o755)


def test_읽을_수_없는_하위_폴더의_파일을_삭제로_오판하지_않는다(tmp_path):
    docs = make_docs(tmp_path, {"top.txt": "위", "sub/a.txt": "아래"})
    run("--snapshot", "./docs", cwd=tmp_path)
    (docs / "sub").chmod(0o000)
    try:
        result = run("--verify", "./docs", cwd=tmp_path)
        assert "삭제된 파일 (1개)" not in result.stdout
        assert result.returncode == checker.EXIT_SCAN_INCOMPLETE
    finally:
        (docs / "sub").chmod(0o755)


def test_읽을_수_없는_하위_폴더가_있으면_스냅샷을_만들지_않는다(tmp_path):
    docs = make_docs(tmp_path, {"sub/a.txt": "아래"})
    (docs / "sub").chmod(0o000)
    try:
        result = run("--snapshot", "./docs", cwd=tmp_path)
        assert result.returncode == checker.EXIT_SCAN_INCOMPLETE
        assert not (tmp_path / checker.SNAPSHOT_FILE).exists()
    finally:
        (docs / "sub").chmod(0o755)


# ─────────────────────────────────────────
# 8. 망가진 스냅샷·키는 크래시 대신 '검증 실패(3)'
# ─────────────────────────────────────────

def tamper_snapshot(tmp_path, **changes):
    snapshot = tmp_path / checker.SNAPSHOT_FILE
    data = json.loads(snapshot.read_text())
    data.update(changes)
    snapshot.write_text(json.dumps(data, ensure_ascii=False))


def test_서명값이_문자열이_아니면_검증_실패(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)
    tamper_snapshot(tmp_path, signature=123)

    assert run("--verify", "./docs", cwd=tmp_path).returncode == checker.EXIT_VERIFICATION_FAILED


def test_서명값에_ASCII가_아닌_글자가_있어도_검증_실패(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)
    tamper_snapshot(tmp_path, signature="é")

    assert run("--verify", "./docs", cwd=tmp_path).returncode == checker.EXIT_VERIFICATION_FAILED


def test_스냅샷을_읽을_권한이_없으면_검증_실패(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)
    snapshot = tmp_path / checker.SNAPSHOT_FILE
    snapshot.chmod(0o000)
    try:
        result = run("--verify", "./docs", cwd=tmp_path)
        assert result.returncode == checker.EXIT_VERIFICATION_FAILED
        assert "Traceback" not in result.stderr
    finally:
        snapshot.chmod(0o644)


def test_UTF8이_아닌_스냅샷은_검증_실패(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    (tmp_path / checker.SNAPSHOT_FILE).write_bytes(b"\xff\xfe garbage")

    result = run("--verify", "./docs", cwd=tmp_path)
    assert result.returncode == checker.EXIT_VERIFICATION_FAILED
    assert "Traceback" not in result.stderr


def test_빈_키_파일로는_검증하지_않는다(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)
    (tmp_path / checker.KEY_FILE).write_text("")

    result = run("--verify", "./docs", cwd=tmp_path)
    assert result.returncode == checker.EXIT_VERIFICATION_FAILED
    assert "무결성이 확인되었습니다" not in result.stdout


def test_빈_키_파일로는_스냅샷을_서명하지_않는다(tmp_path):
    # 빈 키로 서명하면 누구나 같은 서명을 만들 수 있다
    make_docs(tmp_path, {"a.txt": "내용"})
    (tmp_path / checker.KEY_FILE).write_text("")

    result = run("--snapshot", "./docs", cwd=tmp_path)
    assert result.returncode == checker.EXIT_VERIFICATION_FAILED
    assert not (tmp_path / checker.SNAPSHOT_FILE).exists()


# ─────────────────────────────────────────
# 9. 특수 파일과 심볼릭 링크
# ─────────────────────────────────────────

def test_FIFO가_있어도_멈추지_않는다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    os.mkfifo(docs / "pipe")

    result = run("--snapshot", "./docs", cwd=tmp_path)  # 멈추면 timeout 으로 실패

    assert result.returncode == checker.EXIT_OK


def test_깨진_심볼릭_링크가_있어도_스냅샷을_만든다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "내용"})
    os.symlink("/nonexistent/target", docs / "broken")

    assert run("--snapshot", "./docs", cwd=tmp_path).returncode == checker.EXIT_OK


def test_심볼릭_링크의_대상이_바뀌면_변조로_잡는다(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "가", "b.txt": "나"})
    os.symlink("a.txt", docs / "link")
    run("--snapshot", "./docs", cwd=tmp_path)

    (docs / "link").unlink()
    os.symlink("b.txt", docs / "link")
    result = run("--verify", "./docs", cwd=tmp_path)

    assert result.returncode == checker.EXIT_CHANGES_DETECTED
    assert "변조된 파일 (1개)" in result.stdout


def test_실제_폴더를_링크로_바꿔치기하면_잡아낸다(tmp_path):
    docs = make_docs(tmp_path, {"data/x.txt": "원본"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.txt").write_text("공격자 파일")
    run("--snapshot", "./docs", cwd=tmp_path)

    (docs / "data" / "x.txt").unlink()
    (docs / "data").rmdir()
    os.symlink(outside, docs / "data")
    result = run("--verify", "./docs", cwd=tmp_path)

    assert result.returncode == checker.EXIT_CHANGES_DETECTED
    assert "새로 추가된 파일 (1개)" in result.stdout   # 링크 자체가 새로 생겼다
    assert "삭제된 파일 (1개)" in result.stdout        # 원래 있던 data/x.txt


# ─────────────────────────────────────────
# 10. 제외 설정은 스냅샷에 기록되고 서명으로 보호된다
# ─────────────────────────────────────────

def test_스냅샷에_제외_설정이_기록된다(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용", "cache/tmp.bin": "임시"})
    run("--snapshot", "./docs", "--exclude", "cache", cwd=tmp_path)

    data = json.loads((tmp_path / checker.SNAPSHOT_FILE).read_text())
    assert data["exclude_dirs"] == ["cache"]


def test_검증은_스냅샷의_제외_설정을_그대로_쓴다(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용", "cache/tmp.bin": "임시"})
    run("--snapshot", "./docs", "--exclude", "cache", cwd=tmp_path)

    # --exclude 를 다시 주지 않아도 cache/ 가 '추가된 파일'로 잡히지 않아야 한다
    assert run("--verify", "./docs", cwd=tmp_path).returncode == checker.EXIT_OK


def test_검증_때_다른_제외_설정을_주면_거부한다(tmp_path):
    # 검증 때만 몰래 폴더를 빼면 그 안의 변조를 숨길 수 있다
    make_docs(tmp_path, {"a.txt": "내용", ".git/payload": "원본"})
    run("--snapshot", "./docs", cwd=tmp_path)

    result = run("--verify", "./docs", "--exclude", ".git", cwd=tmp_path)
    assert result.returncode == checker.EXIT_USAGE_ERROR


# ─────────────────────────────────────────
# 11. 저장 중 실패해도 기존 기준선은 남는다
# ─────────────────────────────────────────

def test_스냅샷_저장이_중간에_실패해도_기존_기준선은_남는다(tmp_path, monkeypatch, capsys):
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
# 12. 부수 효과와 출력량
# ─────────────────────────────────────────

def test_도움말만_보면_로그_파일을_만들지_않는다(tmp_path):
    run("--help", cwd=tmp_path)
    assert not (tmp_path / checker.LOG_FILE).exists()


def test_파일이_많아도_터미널_출력은_짧다(tmp_path):
    make_docs(tmp_path, {f"f{i}.txt": str(i) for i in range(100)})
    result = run("--snapshot", "./docs", cwd=tmp_path)

    lines = (result.stdout + result.stderr).strip().splitlines()
    assert len(lines) < 10, f"파일 100개에 터미널 {len(lines)}줄"


def test_파일별_기록은_로그_파일에_남는다(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)
    assert "a.txt" in (tmp_path / checker.LOG_FILE).read_text(encoding="utf-8")
