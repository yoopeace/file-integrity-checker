"""명령줄 동작 테스트 (pytest 스타일)

checker.py 를 실제 프로그램처럼 실행해서 종료 코드와 화면 출력을 확인한다.
보안 도구에서 가장 위험한 것은 오류가 나는 것이 아니라
"정상이라고 잘못 확신하게 만드는 것"이다. 그 경우들을 고정한다.

종료 코드 약속
  0: 변경 없음 / 1: 변경 감지 / 2: 사용법·입력 오류
  3: 스냅샷·키 검증 실패 / 4: 일부 파일을 검사하지 못함
"""

import json
import os
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


def make_docs(tmp_path, files):
    """tmp_path/docs 아래에 {경로: 내용} 대로 파일을 만든다."""
    docs = tmp_path / "docs"
    docs.mkdir()
    for name, content in files.items():
        path = docs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return docs


def tamper_snapshot(tmp_path, **changes):
    """스냅샷 파일의 항목을 바꿔치기한다 (공격자 흉내)."""
    snapshot = tmp_path / checker.SNAPSHOT_FILE
    data = json.loads(snapshot.read_text())
    data.update(changes)
    snapshot.write_text(json.dumps(data, ensure_ascii=False))


# ─────────────────────────────────────────
# 1. 종료 코드
# ─────────────────────────────────────────

def test_변경이_없으면_종료코드_0(tmp_path):
    make_docs(tmp_path, {"a.txt": "내용"})
    run("--snapshot", "./docs", cwd=tmp_path)

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 0


def test_변조를_찾으면_종료코드_1(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "원본"})
    run("--snapshot", "./docs", cwd=tmp_path)
    (docs / "a.txt").write_text("변조됨")

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 1


def test_옵션_없이_실행하면_종료코드_2(tmp_path):
    assert run(cwd=tmp_path).returncode == 2


def test_없는_폴더를_지정하면_종료코드_2(tmp_path):
    assert run("--snapshot", "./no_such", cwd=tmp_path).returncode == 2


def test_서명이_어긋나면_종료코드_3(tmp_path):
    docs = make_docs(tmp_path, {"a.txt": "원본"})
    run("--snapshot", "./docs", cwd=tmp_path)

    # 공격자가 파일과 스냅샷 해시를 함께 조작
    (docs / "a.txt").write_text("변조됨")
    snapshot = tmp_path / checker.SNAPSHOT_FILE
    data = json.loads(snapshot.read_text())
    data["files"]["a.txt"] = checker.calculate_hash(str(docs / "a.txt"))
    snapshot.write_text(json.dumps(data))

    assert run("--verify", "./docs", cwd=tmp_path).returncode == 3


# ─────────────────────────────────────────
# 2. 읽을 수 없는 폴더를 '삭제'로 오판하지 않는다
# ─────────────────────────────────────────

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
# 3. 망가진 스냅샷·키는 크래시 대신 '검증 실패(3)'
# ─────────────────────────────────────────

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
# 4. 특수 파일과 심볼릭 링크
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
# 5. 제외 설정은 스냅샷에 기록되고 서명으로 보호된다
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
# 6. 부수 효과와 출력량
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
