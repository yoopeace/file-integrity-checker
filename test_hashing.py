"""해시 계산과 수집, 변조 탐지 테스트 (pytest 스타일)

calculate_hash → collect_hashes → verify_integrity 순서로
파일 지문을 만들고, 폴더 전체를 훑고, 달라진 파일을 찾아낸다.
"""

import os
from pathlib import Path

import checker


# ─────────────────────────────────────────
# 1. calculate_hash: 파일 하나의 지문 만들기
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
# 2. collect_hashes: 폴더 전체 훑기
# ─────────────────────────────────────────

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


# ─────────────────────────────────────────
# 3. verify_integrity: 변조·삭제·추가 탐지
# ─────────────────────────────────────────

def test_변경이_없으면_무결성_확인_메시지를_낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "doc1.txt").write_text("원본")

    checker.create_snapshot("./docs")
    checker.verify_integrity("./docs")

    assert "모든 파일의 무결성이 확인되었습니다" in capsys.readouterr().out


def test_파일_내용이_바뀌면_변조로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "doc1.txt").write_text("원본")

    checker.create_snapshot("./docs")
    (tmp_path / "docs" / "doc1.txt").write_text("몰래 바꾼 내용")
    checker.verify_integrity("./docs")

    output = capsys.readouterr().out
    assert "변조된 파일 (1개)" in output
    assert "doc1.txt" in output


def test_파일이_사라지면_삭제로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "doc1.txt").write_text("원본")

    checker.create_snapshot("./docs")
    (tmp_path / "docs" / "doc1.txt").unlink()
    checker.verify_integrity("./docs")

    assert "삭제된 파일 (1개)" in capsys.readouterr().out


def test_없던_파일이_생기면_추가로_잡아낸다(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "doc1.txt").write_text("원본")

    checker.create_snapshot("./docs")
    (tmp_path / "docs" / "backdoor.txt").write_text("해킹 흔적")
    checker.verify_integrity("./docs")

    output = capsys.readouterr().out
    assert "새로 추가된 파일 (1개)" in output
    assert "backdoor.txt" in output


# ─────────────────────────────────────────
# 4. compare: 비교 로직만 따로 (파일 없이 사전만으로)
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
