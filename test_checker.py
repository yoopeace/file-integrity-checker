import json
import os
import tempfile
import unittest

import checker


class TestComputeSignature(unittest.TestCase):
    def setUp(self):
        self.snapshot = {
            "created_at": "2026-01-01T10:00:00",
            "target_directory": "/tmp/docs",
            "file_count": 1,
            "files": {"doc1.txt": "abc123"},
        }
        self.key = "0" * 64

    def test_같은_데이터와_키는_같은_서명(self):
        sig1 = checker.compute_signature(self.snapshot, self.key)
        sig2 = checker.compute_signature(self.snapshot, self.key)
        self.assertEqual(sig1, sig2)

    def test_해시가_바뀌면_서명이_달라짐(self):
        tampered = json.loads(json.dumps(self.snapshot))
        tampered["files"]["doc1.txt"] = "변조된해시"
        self.assertNotEqual(
            checker.compute_signature(self.snapshot, self.key),
            checker.compute_signature(tampered, self.key),
        )

    def test_키가_다르면_서명이_달라짐(self):
        self.assertNotEqual(
            checker.compute_signature(self.snapshot, self.key),
            checker.compute_signature(self.snapshot, "1" * 64),
        )

    def test_signature_필드_자체는_서명_계산에서_제외(self):
        signed = dict(self.snapshot)
        signed["signature"] = "이미 들어있는 서명"
        self.assertEqual(
            checker.compute_signature(self.snapshot, self.key),
            checker.compute_signature(signed, self.key),
        )


class TestLoadOrCreateKey(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmpdir.name)

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.tmpdir.cleanup()

    def test_키_파일이_없으면_생성(self):
        self.assertFalse(os.path.exists(checker.KEY_FILE))
        key = checker.load_or_create_key()
        self.assertTrue(os.path.exists(checker.KEY_FILE))
        self.assertGreaterEqual(len(key), 32)

    def test_다시_호출하면_같은_키_반환(self):
        key1 = checker.load_or_create_key()
        key2 = checker.load_or_create_key()
        self.assertEqual(key1, key2)


class TestSnapshotSigning(unittest.TestCase):
    """스냅샷 생성 → 서명 포함 여부 및 위변조 탐지 통합 테스트."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmpdir.name)
        os.mkdir("docs")
        with open("docs/doc1.txt", "w") as f:
            f.write("원본 내용")

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.tmpdir.cleanup()

    def test_스냅샷에_서명이_포함됨(self):
        checker.create_snapshot("./docs")
        with open(checker.SNAPSHOT_FILE) as f:
            data = json.load(f)
        self.assertIn("signature", data)
        key = checker.load_or_create_key()
        self.assertEqual(data["signature"], checker.compute_signature(data, key))

    def test_스냅샷_위변조_시_서명_불일치(self):
        checker.create_snapshot("./docs")
        with open(checker.SNAPSHOT_FILE) as f:
            data = json.load(f)
        data["files"]["doc1.txt"] = "0" * 64  # 공격자가 해시를 바꿔치기
        key = checker.load_or_create_key()
        self.assertNotEqual(data["signature"], checker.compute_signature(data, key))


if __name__ == "__main__":
    unittest.main()
