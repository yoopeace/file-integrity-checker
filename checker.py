"""
파일 무결성 검사기 (File Integrity Checker)
--------------------------------------------
디지털 포렌식 기초 프로젝트
- SHA-256 해시로 파일 변조를 탐지합니다.

사용법:
  스냅샷 생성:  python checker.py --snapshot ./검사할폴더
  무결성 검증:  python checker.py --verify  ./검사할폴더
"""

import hashlib      # SHA-256 해시 계산
import hmac         # 스냅샷 서명(위변조 방지)
import json         # 스냅샷 저장/불러오기
import os           # 파일/폴더 탐색
import re           # 출력 정제
import secrets      # 서명용 비밀키 생성
import stat         # 파일 종류(일반 파일·링크·FIFO) 구분
import sys          # 종료 코드 반환
import argparse     # 터미널 명령줄 옵션 처리
import logging      # 로그 파일 기록
from dataclasses import dataclass, field   # 결과를 담는 자료형
from datetime import datetime  # 날짜/시간 기록

# ─────────────────────────────────────────
# 설정값 (원하면 바꿔도 됩니다)
# ─────────────────────────────────────────
# 도구 파일의 기본 위치. 실제로 쓰는 위치는 ToolFiles 가 정합니다.
SNAPSHOT_FILE = "snapshot.json"       # 스냅샷
LOG_FILE      = "integrity_log.txt"   # 검사 기록
KEY_FILE      = ".integrity_key"      # 서명용 비밀키 (--key-file 로 바꿀 수 있음, 유출 주의)

# ─────────────────────────────────────────
# 종료 코드 (자동화 도구가 결과를 판단할 수 있게 구분합니다)
# ─────────────────────────────────────────
EXIT_OK                  = 0   # 변경 없음
EXIT_CHANGES_DETECTED    = 1   # 변조·삭제·추가 감지
EXIT_USAGE_ERROR         = 2   # 사용법 또는 입력 오류
EXIT_VERIFICATION_FAILED = 3   # 스냅샷·키 검증 실패
EXIT_SCAN_INCOMPLETE     = 4   # 일부 파일을 검사하지 못함

# 파일명에 심어 화면을 속이거나 터미널을 조작할 수 있는 보이지 않는 문자
#   - C0·C1 제어문자: ESC 로 시작하는 색상 코드, 0x9b(일부 터미널에서 ESC [ 와 같음), 줄바꿈 등
#   - 글자 방향을 바꾸는 문자 (U+200E·200F, U+202A~202E, U+2066~2069)
#   - 폭 0 문자 (U+200B~200D, U+2060, U+FEFF)
HIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")


def _visible(match: re.Match) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def safe_path(path: str) -> str:
    """
    경로를 화면·기록에 찍기 전에 보이지 않는 문자를 눈에 보이는 표시('\\u202e' 등)로 바꿉니다.

    지우지 않고 바꾸는 이유: 지우면 'ab<U+202E>.txt' 가 진짜 'ab.txt' 와 똑같이 보여
    보고서가 어느 파일을 가리키는지 알 수 없게 됩니다. ESC 도 글자로 바뀌므로
    색상 코드는 터미널이 해석하지 못하는 평범한 글자가 됩니다.
    """
    return HIDDEN_CHARS.sub(_visible, path)


log = logging.getLogger(__name__)


# ─────────────────────────────────────────
# 도구 파일
# ─────────────────────────────────────────
class ToolFiles:
    """
    검사기가 스스로 만들고 쓰는 도구 파일(스냅샷·검사 기록·비밀키)의 위치.
    프로그램이 시작할 때 한 번 만들어, 필요한 함수에 넘깁니다.
    아무것도 지정하지 않으면 지금 폴더의 기본 파일을 씁니다.

    위치는 입력한 형태 그대로 보관해 안내 문구에 씁니다.
    "도구 파일인가?"를 판단할 때 쓰는 실제 위치는 만들 때 한 번 확정해서,
    그 뒤에 현재 폴더가 바뀌어도 판단이 흔들리지 않게 합니다.
    """

    def __init__(self, snapshot: str = SNAPSHOT_FILE, log: str = LOG_FILE,
                 key: str = KEY_FILE):
        self.snapshot = snapshot
        self.log = log
        self.key = key
        # 저장 중 임시 파일의 이름은 스냅샷 저장소가 정하므로 그쪽에 묻습니다
        locations = (snapshot, snapshot_temp_path(snapshot), log, key)
        self._real_paths = frozenset(os.path.realpath(p) for p in locations)

    def includes(self, path: str) -> bool:
        """path 가 도구 파일이면 True. 같은 파일을 다른 표기로 가리켜도 알아봅니다."""
        return os.path.realpath(path) in self._real_paths


def setup_logging(tool_files: ToolFiles) -> None:
    """검사 이력을 로그 파일에 남깁니다.

    import 시점이 아니라 실행할 때 설정해야 --help 만 봐도 파일이 생기는 일이 없습니다.
    화면 출력은 print 가 맡고, 로그는 파일에만 씁니다. 파일별 기록까지 터미널에
    찍으면 파일 수만큼 줄이 쏟아져 정작 결과 보고서가 묻힙니다.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)s  %(message)s",
        handlers=[logging.FileHandler(tool_files.log, encoding="utf-8")],
    )


# ─────────────────────────────────────────
# 핵심 함수 1: SHA-256 해시 계산
# ─────────────────────────────────────────
def calculate_hash(filepath: str) -> str:
    """
    파일 하나의 SHA-256 해시값을 계산합니다.
    
    SHA-256 이란?
      - 어떤 파일이든 256비트(64자리 16진수) 고유 '지문'을 만듭니다.
      - 파일 내용이 1바이트라도 바뀌면 완전히 다른 해시가 나옵니다.
      - 역방향 복원이 불가능해 무결성 검증에 표준으로 쓰입니다.
    """
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:   # 바이너리 모드로 읽어야 해시가 정확합니다
        # 대용량 파일도 처리할 수 있도록 4KB씩 나눠서 읽습니다
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()          # 예: "a3f2b1c9d4..."


def fingerprint(filepath: str) -> str:
    """
    폴더 안 항목 하나의 지문을 만듭니다.

    - 일반 파일: 내용의 SHA-256
    - 심볼릭 링크: 따라가지 않고 '어디를 가리키는지'를 기록
      (따라가면 깨진 링크에서 실패하고, 폴더를 링크로 바꿔치기해도 알아채지 못합니다)
    - FIFO·장치 파일 등: 열면 멈출 수 있어 내용은 읽지 않고 종류만 기록
    """
    mode = os.lstat(filepath).st_mode
    if stat.S_ISLNK(mode):
        return "symlink:" + os.readlink(filepath)
    if not stat.S_ISREG(mode):
        kind = "fifo" if stat.S_ISFIFO(mode) else "socket" if stat.S_ISSOCK(mode) else "device"
        return "special:" + kind
    return calculate_hash(filepath)


# ─────────────────────────────────────────
# 핵심 함수 2: 폴더 내 모든 파일 해시 수집
# ─────────────────────────────────────────
@dataclass(frozen=True)
class Scan:
    """
    폴더를 한 번 훑은 결과.

    hashes : {상대경로: 지문}
    errors : {상대경로: 실패 이유}  읽지 못한 파일·폴더. 검사 폴더 자체를 못 열면 "." 으로 기록됩니다.

    실패 목록을 어떻게 기록하는지(collect_hashes)와 어떻게 해석하는지(is_unverifiable)를
    이 값 한 곳에 둡니다. 둘이 떨어져 있으면 한쪽 규칙만 바뀌어도 알아챌 수 없습니다.
    """
    hashes: dict
    errors: dict

    def is_unverifiable(self, path: str) -> bool:
        """path 자체를, 또는 path 가 들어 있는 폴더를 읽지 못했는지 확인합니다."""
        return any(
            path == failed or failed == "." or path.startswith(failed + os.sep)
            for failed in self.errors
        )


def collect_hashes(directory: str, exclude_dirs=(), tool_files: ToolFiles | None = None) -> Scan:
    """
    지정한 폴더 안의 모든 파일에 대해 해시를 계산합니다.

    읽지 못한 파일을 조용히 건너뛰면 이후 비교에서 '삭제됨'으로 오판하게 되므로
    실패 목록도 함께 돌려주어 호출한 쪽이 판단하게 합니다.

    숨김 폴더도 기본으로 검사합니다. 보안 검사에서는 오히려 숨김 폴더에
    중요한 파일이 있을 수 있으므로, 제외는 exclude_dirs 로 명시해야 합니다.
    """
    hashes = {}
    errors = {}
    directory = os.path.abspath(directory)   # 절대 경로로 통일

    # 도구가 실제로 만든 파일만 경로로 판단해 제외합니다.
    # 이름만 보고 제외하면 사용자의 backup/snapshot.json 까지 검사에서 빠집니다.
    tool_files = tool_files or ToolFiles()

    def record_unreadable_dir(error: OSError) -> None:
        # os.walk 는 열지 못한 폴더를 기본적으로 조용히 건너뜁니다.
        # 그러면 그 안의 파일이 모두 '삭제됨'으로 보이므로 실패로 기록합니다.
        relative_dir = os.path.relpath(error.filename, directory)
        errors[relative_dir] = str(error)
        log.error(f"  검사 실패(폴더): {safe_path(relative_dir)} → {error}")

    for root, dirs, files in os.walk(directory, onerror=record_unreadable_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        # 폴더를 가리키는 링크는 os.walk 가 따라 들어가지 않으므로 링크 자체를 기록합니다
        linked_dirs = [d for d in dirs if os.path.islink(os.path.join(root, d))]

        for filename in files + linked_dirs:
            filepath = os.path.join(root, filename)
            if tool_files.includes(filepath):
                continue

            # 폴더 경로를 제거한 상대 경로를 키로 사용
            relative_path = os.path.relpath(filepath, directory)

            try:
                hashes[relative_path] = fingerprint(filepath)
                log.info(f"  해시 계산 완료: {safe_path(relative_path)}")
            except OSError as e:
                errors[relative_path] = str(e)
                log.error(f"  검사 실패: {safe_path(relative_path)} → {e}")

    return Scan(hashes, errors)


# ─────────────────────────────────────────
# 비밀키
# ─────────────────────────────────────────
# 키를 쓰는 정책은 두 가지이고, 서로 섞이면 안 됩니다.
#   - 서명할 때: 키가 없으면 새로 만든다
#   - 검증할 때: 키가 없으면 그대로 실패한다 (절대 새로 만들지 않는다)
# 검증하는 쪽이 키를 새로 만들면, 엉뚱한 새 키로 서명을 확인하게 됩니다.

class KeyUnavailable(Exception):
    """비밀키를 쓸 수 없음. missing 이 True 면 키 파일이 아예 없는 경우입니다."""

    def __init__(self, message: str, missing: bool = False):
        super().__init__(message)
        self.missing = missing


def key_for_verifying(key_file: str = KEY_FILE) -> str:
    """검증용 비밀키를 읽습니다. 없거나, 비었거나, 읽을 수 없으면 KeyUnavailable."""
    try:
        with open(key_file, "r", encoding="utf-8") as f:
            key = f.read().strip()
    except FileNotFoundError as e:
        raise KeyUnavailable(str(e), missing=True) from e
    except (OSError, ValueError) as e:   # ValueError: UTF-8 이 아닌 내용
        raise KeyUnavailable(str(e)) from e
    # 빈 키로 서명하면 누구나 같은 서명을 만들 수 있습니다
    if not key:
        raise KeyUnavailable(f"비밀키 파일({safe_path(key_file)})이 비어 있습니다")
    return key


def key_for_signing(key_file: str = KEY_FILE) -> tuple:
    """
    서명용 비밀키를 돌려줍니다. 없으면 새로 만듭니다.
    반환값: (키, 이번에 새로 만들었는지)

    공격자가 파일을 바꾼 뒤 snapshot.json까지 함께 조작하면
    해시 비교만으로는 탐지할 수 없습니다.
    비밀키로 스냅샷에 서명해 두면 스냅샷 자체의 위변조를 잡아낼 수 있습니다.
    (단, 키 파일이 유출되면 무력화되므로 안전한 곳에 보관해야 합니다.
     스냅샷을 수정할 수 있는 사람이 키도 읽을 수 있으면 의미가 없으므로,
     key_file 로 USB 등 검사 대상과 다른 곳을 지정하는 것이 좋습니다.)
    """
    try:
        return key_for_verifying(key_file), False
    except KeyUnavailable as e:
        if not e.missing:
            raise

    key = secrets.token_hex(32)   # 256비트 무작위 키
    # 처음부터 소유자 전용 권한(600)으로 만듭니다. 일반 권한으로 만든 뒤 바꾸면
    # 그 사이 잠깐 같은 컴퓨터의 다른 사용자가 키를 읽을 수 있습니다.
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        raise KeyUnavailable(str(e)) from e
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    log.info(f"  서명용 비밀키 생성: {key_file}")
    return key, True


# ─────────────────────────────────────────
# 스냅샷 저장소
# ─────────────────────────────────────────
# "이 스냅샷을 믿어도 되는가"를 이 구역 한 곳에서 판단합니다.
# 저장할 때 서명하고, 불러올 때 형식과 서명을 끝까지 확인합니다.
# 화면 출력은 하지 않습니다. 실패는 SnapshotRejected 로, 이유를 담아 알립니다.

def compute_signature(snapshot_data: dict, key: str) -> str:
    """
    스냅샷 내용 전체에 대한 HMAC-SHA256 서명을 계산합니다.
    signature 필드 자체는 계산에서 제외합니다.
    """
    payload = {k: v for k, v in snapshot_data.items() if k != "signature"}
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    """형식 검사를 통과한 스냅샷."""
    created_at: str | None
    target_directory: str | None
    exclude_dirs: list
    files: dict                        # 상대 경로 → 지문
    # None 이면 서명까지 확인된 '신뢰할 수 있는 스냅샷'.
    # 값이 있으면 서명을 확인하지 못한 '확인 안 된 스냅샷' ("unsigned" 또는 "key_missing")
    unverified_reason: str | None = None


class SnapshotRejected(Exception):
    """
    스냅샷을 믿을 수 없어 쓰지 않음. reason 은 다음 중 하나입니다.
      missing · unreadable · malformed · unsigned · key_missing · key_unusable · signature_mismatch
    """

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def snapshot_temp_path(snapshot_path: str = SNAPSHOT_FILE) -> str:
    """저장 중에만 잠깐 존재하는 임시 파일 경로. 이 이름은 이 함수만 압니다."""
    return snapshot_path + ".tmp"


def save_snapshot(directory: str, hashes: dict, exclude_dirs, key: str,
                  snapshot_path: str = SNAPSHOT_FILE) -> None:
    """
    현재 상태를 서명해서 저장합니다. 이것이 나중에 비교할 기준선이 됩니다.
    저장에 실패하면 OSError 를 그대로 던지고, 이전 스냅샷은 건드리지 않습니다.
    """
    snapshot_data = {
        "created_at": datetime.now().isoformat(),
        "target_directory": os.path.abspath(directory),
        # 제외 설정도 서명 대상에 넣습니다. 검증 때 몰래 다른 폴더를 빼서
        # 그 안의 변조를 숨기는 것을 막기 위해서입니다.
        "exclude_dirs": sorted(exclude_dirs),
        "file_count": len(hashes),
        "files": hashes
    }
    snapshot_data["signature"] = compute_signature(snapshot_data, key)

    # 임시 파일에 다 쓴 뒤 한 번에 바꿔치기합니다. 기존 파일에 바로 쓰다가
    # 디스크가 차거나 중단되면 하나뿐인 기준선이 반쯤 쓰인 채 망가집니다.
    temp_file = snapshot_temp_path(snapshot_path)
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, snapshot_path)
    except OSError:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        raise


def load_snapshot(snapshot_path: str = SNAPSHOT_FILE, key_file: str = KEY_FILE,
                  allow_unsigned: bool = False) -> Snapshot:
    """
    스냅샷을 읽고 형식과 서명을 끝까지 확인해서 돌려줍니다.
    믿을 수 없으면 SnapshotRejected 를 던집니다.

    서명을 확인할 수 없으면(서명 없음·키 없음) 기본적으로 거부합니다(fail-closed).
    allow_unsigned 면 거부하지 않고 '확인 안 된 스냅샷'으로 돌려줍니다.
    서명을 확인했는데 틀린 경우는 allow_unsigned 여도 거부합니다.
    """
    # ValueError: 깨진 JSON, UTF-8 이 아닌 바이트 / OSError: 읽기 권한 없음 등
    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as e:
        raise SnapshotRejected("missing") from e
    except (OSError, ValueError) as e:
        raise SnapshotRejected("unreadable", str(e)) from e

    # JSON 은 유효해도 스냅샷 형식이 아니면 거부합니다. 값의 타입까지 확인해야
    # 이후 단계가 형식을 걱정하지 않고 쓸 수 있습니다.
    if not isinstance(data, dict):
        raise SnapshotRejected("malformed")
    files = data.get("files")
    exclude_dirs = data.get("exclude_dirs", [])
    created_at = data.get("created_at")
    target_directory = data.get("target_directory")
    if not (isinstance(files, dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in files.items())
            and isinstance(exclude_dirs, list)
            and all(isinstance(d, str) for d in exclude_dirs)
            and (created_at is None or isinstance(created_at, str))
            and (target_directory is None or isinstance(target_directory, str))):
        raise SnapshotRejected("malformed")

    # 스냅샷 자체가 위변조되지 않았는지 서명 확인
    unverified_reason = None
    signature = data.get("signature")
    if signature is None:
        unverified_reason = "unsigned"
    else:
        try:
            key = key_for_verifying(key_file)
        except KeyUnavailable as e:
            if not e.missing:
                raise SnapshotRejected("key_unusable", str(e)) from e
            unverified_reason = "key_missing"
        else:
            expected = compute_signature(data, key)
            # 서명값은 조작될 수 있는 입력이므로 문자열인지부터 확인합니다.
            # bytes 로 비교해야 ASCII 가 아닌 글자가 섞여도 예외 없이 '불일치'로 처리됩니다.
            valid = (isinstance(signature, str)
                     and hmac.compare_digest(expected.encode(), signature.encode("utf-8")))
            if not valid:
                raise SnapshotRejected("signature_mismatch")

    if unverified_reason and not allow_unsigned:
        raise SnapshotRejected(unverified_reason)

    return Snapshot(created_at, target_directory, list(exclude_dirs), dict(files),
                    unverified_reason)


# ─────────────────────────────────────────
# 기능 A: 스냅샷 저장
# ─────────────────────────────────────────
def print_key_unavailable(error, tool_files: ToolFiles) -> None:
    """비밀키를 쓸 수 없을 때의 안내."""
    print(f"\n❌ 비밀키를 사용할 수 없습니다: {error}")
    print(f"   {safe_path(tool_files.key)} 를 확인해 주세요.\n")
    log.error(f"  비밀키 사용 불가: {error}")


def create_snapshot(directory: str, exclude_dirs=(), tool_files: ToolFiles | None = None) -> int:
    """
    현재 상태(해시 딕셔너리)를 서명해서 snapshot.json에 저장합니다.
    이것이 나중에 비교할 '기준선(baseline)'이 됩니다.
    """
    if not os.path.isdir(directory):
        print(f"\n❌ 폴더를 찾을 수 없습니다: {safe_path(directory)}")
        print("   경로를 다시 확인해 주세요.\n")
        return EXIT_USAGE_ERROR

    tool_files = tool_files or ToolFiles()
    log.info(f"=== 스냅샷 생성 시작: {directory} ===")
    scan = collect_hashes(directory, exclude_dirs, tool_files)

    # 일부를 읽지 못한 상태로 기준선을 만들면 이후 검증 결과를 신뢰할 수 없습니다
    if scan.errors:
        print(f"\n❌ 검사하지 못한 파일·폴더가 {len(scan.errors)}개 있어 스냅샷을 만들지 않았습니다.")
        for path, reason in scan.errors.items():
            print(f"   • {safe_path(path)} → {safe_path(reason)}")
        print("   권한을 확인한 뒤 다시 시도해 주세요.\n")
        log.error(f"=== 스냅샷 중단: 검사 실패 {len(scan.errors)}건 ===")
        return EXIT_SCAN_INCOMPLETE

    try:
        key, key_created = key_for_signing(tool_files.key)
    except KeyUnavailable as e:
        print_key_unavailable(e, tool_files)
        return EXIT_VERIFICATION_FAILED
    if key_created:
        # 키를 다른 곳에 둘수록 어디에 만들어졌는지 놓치기 쉬우므로 화면에 알립니다
        print(f"\n🔑 새 비밀키를 만들었습니다: {safe_path(tool_files.key)}")
        print("   이 키가 있어야 검증할 수 있습니다. 검사 대상과 다른 곳에 안전하게 보관하세요.")

    try:
        save_snapshot(directory, scan.hashes, exclude_dirs, key, tool_files.snapshot)
    except OSError as e:
        print(f"\n❌ 스냅샷을 저장하지 못했습니다: {e}")
        print("   이전 스냅샷이 있었다면 그대로 남아 있습니다.\n")
        log.error(f"=== 스냅샷 저장 실패: {e} ===")
        return EXIT_USAGE_ERROR

    log.info(f"=== 스냅샷 완료: {len(scan.hashes)}개 파일 → {tool_files.snapshot} ===")
    print(f"\n✅ 스냅샷 저장 완료: {len(scan.hashes)}개 파일이 기록되었습니다.")
    return EXIT_OK


# ─────────────────────────────────────────
# 기능 B: 무결성 검증
# ─────────────────────────────────────────
# 검증은 판단과 출력을 나눕니다.
#   run_verification     : 스냅샷 확인 → 거부할지·주의할지 판단 → 비교. 결과를 값(VerifyOutcome)으로
#   print_verify_outcome : 그 값을 화면에 그림
#   verify_integrity     : 둘을 차례로 부르고 종료 코드를 돌려줌 (CLI 용)
# 판단을 출력과 떼어 두면, 결과를 화면 문구가 아니라 값으로 확인할 수 있습니다.

@dataclass
class Comparison:
    """기준선과 현재 상태를 비교한 결과."""
    modified: list       # 내용이 바뀐 파일
    deleted: list        # 삭제된 파일
    added: list          # 새로 생긴 파일
    unverifiable: dict   # 읽지 못한 파일·폴더 → 실패 이유

    @property
    def change_count(self) -> int:
        return len(self.modified) + len(self.deleted) + len(self.added)

    def exit_code(self) -> int:
        # 일부를 확인하지 못했으면, 변경이 있든 없든 결과를 확정할 수 없습니다
        if self.unverifiable:
            return EXIT_SCAN_INCOMPLETE
        return EXIT_CHANGES_DETECTED if self.change_count else EXIT_OK


@dataclass(frozen=True)
class Caution:
    """검증은 계속하지만, 결과를 해석할 때 주의할 점."""
    kind: str          # "unverified"      : 서명 확인을 건너뜀       (detail: (이유,))
                       # "target_mismatch" : 스냅샷과 다른 폴더를 검증 (detail: (스냅샷 기준 폴더, 지금 검사한 폴더))
    detail: tuple = ()


@dataclass(frozen=True)
class Refusal:
    """검증을 하지 않은 이유."""
    kind: str          # "snapshot_rejected" : 스냅샷을 믿을 수 없음   (detail: SnapshotRejected)
                       # "target_missing"    : 검사 폴더가 없음         (detail: 입력한 폴더 경로)
                       # "exclude_mismatch"  : 제외 설정이 스냅샷과 다름 (detail: (스냅샷의 제외, 요청한 제외))
    detail: object = None

    @property
    def exit_code(self) -> int:
        # 스냅샷이 아예 없거나 입력이 잘못된 경우는 사용법 오류, 스냅샷을 믿을 수 없으면 검증 실패
        if self.kind == "snapshot_rejected" and self.detail.reason != "missing":
            return EXIT_VERIFICATION_FAILED
        return EXIT_USAGE_ERROR


@dataclass
class VerifyOutcome:
    """검증 한 번의 결과. 판단(run_verification)과 출력(print_verify_outcome)을 잇습니다."""
    cautions: list = field(default_factory=list)   # 발생한 순서대로
    refusal: Refusal | None = None
    comparison: Comparison | None = None            # 거부되지 않았을 때만 있음
    created_at: str = "알 수 없음"                   # 스냅샷 만든 시각 (조작됐을 수 있어 출력 전 정제)
    scanned_count: int = 0

    @property
    def exit_code(self) -> int:
        if self.refusal:
            return self.refusal.exit_code
        return self.comparison.exit_code()


def compare(old_hashes: dict, current: Scan) -> Comparison:
    """
    기준선(old_hashes)과 지금 훑은 결과(current)를 비교합니다.
    파일을 읽지 않고 값만 다루므로, 테스트에서 Scan 을 직접 만들어 바로 확인할 수 있습니다.
    """
    modified = []
    deleted = []
    for filepath, old_hash in old_hashes.items():
        # 읽지 못한 파일(또는 읽지 못한 폴더 안의 파일)은 '삭제'가 아니라 '검사 실패'입니다.
        # 둘을 섞으면 멀쩡히 있는 파일을 삭제됐다고 보고하게 됩니다.
        if current.is_unverifiable(filepath):
            continue
        if filepath not in current.hashes:
            deleted.append(filepath)
        elif current.hashes[filepath] != old_hash:
            modified.append(filepath)

    added = [filepath for filepath in current.hashes if filepath not in old_hashes]
    return Comparison(modified, deleted, added, dict(current.errors))


# 보고서에 찍는 시각 형식. 스냅샷 기준 시각과 검사 완료 시각을 같은 모양으로 보여 줍니다.
DISPLAY_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'


def display_time(stored: str) -> str:
    """
    스냅샷에 저장된 시각(ISO 형식, 마이크로초 포함)을 보고서용 형식으로 바꿉니다.
    저장된 값은 서명 대상이라 그대로 두고, 화면에 보일 때만 바꿉니다.
    시각으로 읽을 수 없는 값('알 수 없음', 조작된 값)은 정제만 해서 그대로 보여 줍니다.
    """
    try:
        return datetime.fromisoformat(stored).strftime(DISPLAY_TIME_FORMAT)
    except (TypeError, ValueError):
        return safe_path(stored)


def print_report(result: Comparison, created_at: str, scanned_count: int) -> None:
    """비교 결과를 보고서 형식으로 화면에 출력합니다."""
    print("\n" + "="*50)
    print("    📋 무결성 검사 결과 보고서")
    print("="*50)
    print(f"  스냅샷 기준 시각: {created_at}")
    print(f"  검사 완료 시각:   {datetime.now().strftime(DISPLAY_TIME_FORMAT)}")
    print(f"  검사 파일 수:     {scanned_count}개")
    print("-"*50)

    if result.modified:
        print(f"\n⚠️  변조된 파일 ({len(result.modified)}개):")
        for f in result.modified:
            print(f"   • {safe_path(f)}")
    else:
        print("\n✅ 변조된 파일: 없음")

    if result.deleted:
        print(f"\n🗑️  삭제된 파일 ({len(result.deleted)}개):")
        for f in result.deleted:
            print(f"   • {safe_path(f)}")
    else:
        print("✅ 삭제된 파일: 없음")

    if result.added:
        print(f"\n📄 새로 추가된 파일 ({len(result.added)}개):")
        for f in result.added:
            print(f"   • {safe_path(f)}")
    else:
        print("✅ 새로 추가된 파일: 없음")

    if result.unverifiable:
        print(f"\n❓ 검사하지 못한 파일·폴더 ({len(result.unverifiable)}개):")
        for f, reason in result.unverifiable.items():
            print(f"   • {safe_path(f)} → {safe_path(reason)}")

    print("="*50)

    total = result.change_count
    if result.unverifiable:
        # 일부를 확인하지 못했으므로 '이상 없음'이라고 단언할 수 없습니다
        print(f"\n⚠️  검사하지 못한 파일·폴더가 {len(result.unverifiable)}개 있어 결과를 확정할 수 없습니다.")
        if total:
            print(f"   확인된 변경은 {total}건입니다.")
        print()
    elif total == 0:
        print("\n🎉 모든 파일의 무결성이 확인되었습니다!\n")
    else:
        print(f"\n🚨 총 {total}건의 변경이 감지되었습니다. 로그를 확인하세요.\n")


def print_rejection(error: SnapshotRejected, tool_files: ToolFiles) -> None:
    """스냅샷 저장소가 거부한 이유를 안내 문구로 출력합니다."""
    if error.reason == "missing":
        print(f"\n❌ 스냅샷 파일({safe_path(tool_files.snapshot)})이 없습니다.")
        print("   먼저 --snapshot 옵션으로 기준선을 만들어 주세요.\n")
    elif error.reason == "unreadable":
        print(f"\n❌ 스냅샷 파일({safe_path(tool_files.snapshot)})을 읽을 수 없습니다: {safe_path(error.detail)}")
        print("   손상되었다면 --snapshot 옵션으로 다시 생성해 주세요.\n")
    elif error.reason == "malformed":
        print(f"\n❌ 스냅샷 파일({safe_path(tool_files.snapshot)})의 형식이 올바르지 않습니다.")
        print("   --snapshot 옵션으로 다시 생성해 주세요.\n")
    elif error.reason in ("unsigned", "key_missing"):
        reason = unverified_description(error.reason, tool_files)
        print(f"\n🚨 검증을 중단합니다: {reason}.")
        print("   스냅샷 자체의 위변조 여부를 확인할 수 없어 결과를 신뢰할 수 없습니다.")
        if error.reason == "key_missing":
            print("   키를 다른 곳에 보관한다면 --key-file 로 위치를 지정해 주세요.")
        print("   --snapshot 으로 기준선을 다시 만들거나,")
        print("   위험을 감수하고 진행하려면 --allow-unsigned 를 명시해 주세요.\n")
        log.error(f"  서명 검증 불가({reason}) - 검증 중단")
    elif error.reason == "key_unusable":
        print_key_unavailable(error.detail, tool_files)
    else:  # signature_mismatch
        print(f"\n🚨 경고: 스냅샷 파일({safe_path(tool_files.snapshot)})의 서명이 일치하지 않습니다!")
        print("   스냅샷 자체가 위변조되었을 가능성이 있어 검증을 중단합니다.")
        print("   (키를 여러 개 쓴다면, 스냅샷을 만들 때 쓴 키를 --key-file 로 지정했는지 확인해 주세요.)")
        print("   신뢰할 수 있는 기준선이 필요하면 --snapshot 으로 다시 생성해 주세요.\n")
        log.error("  스냅샷 서명 불일치 - 위변조 의심, 검증 중단")


def unverified_description(reason: str, tool_files: ToolFiles) -> str:
    """서명을 확인하지 못한 이유를 사람이 읽을 문장으로."""
    if reason == "unsigned":
        return "서명이 없는 스냅샷입니다 (구버전에서 생성)"
    return f"비밀키 파일({safe_path(tool_files.key)})이 없습니다"


def run_verification(directory: str, exclude_dirs=None, allow_unsigned: bool = False,
                     tool_files: ToolFiles | None = None) -> VerifyOutcome:
    """
    현재 상태와 스냅샷을 비교해 변조/추가/삭제된 파일을 찾고, 결과를 값으로 돌려줍니다.
    이것이 디지털 포렌식의 핵심 개념입니다!
    화면에는 아무것도 출력하지 않습니다 (검사 기록 로그만 남깁니다).

    exclude_dirs 를 생략하면 스냅샷에 기록된 제외 설정을 그대로 씁니다.
    다른 값을 주면 거부합니다.
    """
    tool_files = tool_files or ToolFiles()
    outcome = VerifyOutcome()

    # 1) 스냅샷 읽기·서명 확인
    try:
        snapshot = load_snapshot(tool_files.snapshot, tool_files.key, allow_unsigned)
    except SnapshotRejected as e:
        outcome.refusal = Refusal("snapshot_rejected", e)
        return outcome

    if not os.path.isdir(directory):
        outcome.refusal = Refusal("target_missing", directory)
        return outcome

    if snapshot.unverified_reason:
        outcome.cautions.append(Caution("unverified", (snapshot.unverified_reason,)))
        reason = unverified_description(snapshot.unverified_reason, tool_files)
        log.warning(f"  서명 검증 생략({reason}) - allow_unsigned")

    # 제외 설정은 스냅샷(서명으로 보호됨)에 기록된 것을 기준으로 합니다
    if exclude_dirs is not None and set(exclude_dirs) != set(snapshot.exclude_dirs):
        outcome.refusal = Refusal("exclude_mismatch", (snapshot.exclude_dirs, exclude_dirs))
        log.error("  제외 설정 불일치 - 검증 중단")
        return outcome

    log.info(f"=== 무결성 검증 시작: {directory} ===")
    outcome.created_at = snapshot.created_at or "알 수 없음"

    # 검증 대상 폴더가 스냅샷 생성 당시 폴더와 다르면 주의
    current_dir = os.path.abspath(directory)
    if snapshot.target_directory and current_dir != snapshot.target_directory:
        outcome.cautions.append(Caution("target_mismatch", (snapshot.target_directory, current_dir)))
        log.warning(f"  대상 폴더 불일치 - 스냅샷: {snapshot.target_directory} / 검증: {current_dir}")

    # 2) 현재 상태를 읽어 비교
    current = collect_hashes(directory, set(snapshot.exclude_dirs), tool_files)
    result = compare(snapshot.files, current)
    outcome.comparison = result
    outcome.scanned_count = len(current.hashes)

    for f in result.deleted:
        log.warning(f"  [삭제] {safe_path(f)}")
    for f in result.modified:
        log.warning(f"  [변조] {safe_path(f)}")
    for f in result.added:
        log.info(f"  [추가] {safe_path(f)}")
    log.info(
        f"=== 검증 완료: 변조 {len(result.modified)}건, 삭제 {len(result.deleted)}건, "
        f"추가 {len(result.added)}건, 검사실패 {len(result.unverifiable)}건 ==="
    )
    return outcome


def print_verify_outcome(outcome: VerifyOutcome, tool_files: ToolFiles) -> None:
    """검증 결과를 화면에 그립니다. 항상 '주의 → 거부 안내 또는 보고서' 순서입니다."""
    for caution in outcome.cautions:
        if caution.kind == "unverified":
            reason = unverified_description(caution.detail[0], tool_files)
            print(f"\n⚠️  주의: {reason}. --allow-unsigned 지정으로 검증을 계속합니다.")
            print("   스냅샷 자체의 위변조 여부는 확인되지 않았습니다.")
        elif caution.kind == "target_mismatch":
            baseline_dir, current_dir = caution.detail
            print(f"\n⚠️  주의: 스냅샷은 '{safe_path(baseline_dir)}' 폴더 기준으로 생성되었습니다.")
            print(f"   현재 검증 대상('{safe_path(current_dir)}')과 다릅니다. 결과 해석에 유의하세요.")

    refusal = outcome.refusal
    if refusal is None:
        # 스냅샷에서 읽은 값은 화면에 찍기 전에 정제합니다 (--allow-unsigned 면 조작됐을 수 있음)
        print_report(outcome.comparison, display_time(outcome.created_at), outcome.scanned_count)
    elif refusal.kind == "snapshot_rejected":
        print_rejection(refusal.detail, tool_files)
    elif refusal.kind == "target_missing":
        print(f"\n❌ 폴더를 찾을 수 없습니다: {safe_path(refusal.detail)}")
        print("   경로를 다시 확인해 주세요.\n")
    else:  # exclude_mismatch
        recorded, requested = refusal.detail

        def describe(dirs):
            return ", ".join(safe_path(d) for d in sorted(dirs)) or "없음"
        print("\n❌ 제외 설정이 스냅샷과 다릅니다.")
        print(f"   스냅샷: {describe(recorded)} / 지금: {describe(requested)}")
        print("   --exclude 를 생략하면 스냅샷에 기록된 설정을 그대로 사용합니다.\n")


def verify_integrity(directory: str, exclude_dirs=None, allow_unsigned: bool = False,
                     tool_files: ToolFiles | None = None) -> int:
    """검증하고, 결과를 화면에 출력한 뒤 종료 코드를 돌려줍니다 (CLI 용)."""
    tool_files = tool_files or ToolFiles()
    outcome = run_verification(directory, exclude_dirs, allow_unsigned, tool_files)
    print_verify_outcome(outcome, tool_files)
    return outcome.exit_code


# ─────────────────────────────────────────
# 터미널 명령줄 처리 (메인 진입점)
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="파일 무결성 검사기 — SHA-256 기반 변조 탐지 도구",
        epilog="예시:\n  python checker.py --snapshot ./documents\n  python checker.py --verify ./documents",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--snapshot", metavar="폴더경로",
                        help="지정 폴더의 스냅샷(기준선)을 생성합니다.")
    group.add_argument("--verify",   metavar="폴더경로",
                        help="스냅샷과 현재 상태를 비교해 변조를 탐지합니다.")
    parser.add_argument("--exclude", metavar="폴더명", action="append", default=[],
                        help="검사에서 제외할 폴더 이름 (여러 번 지정 가능, 예: --exclude .git)\n"
                             "스냅샷에 기록되며, 검증 때 생략하면 같은 설정이 적용됩니다.")
    parser.add_argument("--key-file", metavar="경로", default=KEY_FILE,
                        help=f"서명용 비밀키 파일 위치 (기본: {KEY_FILE})\n"
                             "USB 등 검사 대상과 다른 곳에 두면 스냅샷을 조작한 사람도 키를 읽지 못합니다.")
    parser.add_argument("--allow-unsigned", action="store_true",
                        help="서명이나 비밀키가 없어도 검증을 진행합니다 (신뢰도가 낮아집니다).")

    args = parser.parse_args()
    tool_files = ToolFiles(key=args.key_file)
    setup_logging(tool_files)

    if args.snapshot:
        return create_snapshot(args.snapshot, set(args.exclude), tool_files)
    if args.verify:
        return verify_integrity(args.verify, set(args.exclude) if args.exclude else None,
                                args.allow_unsigned, tool_files)

    parser.print_help()
    return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
