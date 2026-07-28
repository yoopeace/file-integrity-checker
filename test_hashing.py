"""해시 계산과 수집, 변조 탐지 테스트 (pytest 스타일)

calculate_hash → collect_hashes → verify_integrity 순서로
파일 지문을 만들고, 폴더 전체를 훑고, 달라진 파일을 찾아낸다.
"""

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

    result = checker.collect_hashes(str(tmp_path))

    assert "top.txt" in result
    assert "sub/inner.txt" in result


def test_숨김_폴더는_건너뛴다(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("깃 내부 파일")
    (tmp_path / "real.txt").write_text("진짜 파일")

    result = checker.collect_hashes(str(tmp_path))

    assert list(result.keys()) == ["real.txt"]


def test_도구가_만든_파일은_검사_대상에서_제외한다(tmp_path):
    (tmp_path / checker.SNAPSHOT_FILE).write_text("{}")
    (tmp_path / checker.LOG_FILE).write_text("로그")
    (tmp_path / checker.KEY_FILE).write_text("비밀키")
    (tmp_path / "user.txt").write_text("사용자 파일")

    result = checker.collect_hashes(str(tmp_path))

    assert list(result.keys()) == ["user.txt"]


def test_빈_폴더는_빈_결과를_돌려준다(tmp_path):
    assert checker.collect_hashes(str(tmp_path)) == {}


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
