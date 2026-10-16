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
from datetime import datetime  # 날짜/시간 기록

# ─────────────────────────────────────────
# 설정값 (원하면 바꿔도 됩니다)
# ─────────────────────────────────────────
SNAPSHOT_FILE = "snapshot.json"       # 해시 저장 파일 이름
LOG_FILE      = "integrity_log.txt"   # 로그 파일 이름
KEY_FILE      = ".integrity_key"      # 스냅샷 서명용 비밀키 파일 (유출 주의)

# ─────────────────────────────────────────
# 종료 코드 (자동화 도구가 결과를 판단할 수 있게 구분합니다)
# ─────────────────────────────────────────
EXIT_OK                  = 0   # 변경 없음
EXIT_CHANGES_DETECTED    = 1   # 변조·삭제·추가 감지
EXIT_USAGE_ERROR         = 2   # 사용법 또는 입력 오류
EXIT_VERIFICATION_FAILED = 3   # 스냅샷·키 검증 실패
EXIT_SCAN_INCOMPLETE     = 4   # 일부 파일을 검사하지 못함

# 파일명에 심어진 제어문자로 출력을 조작하는 것을 막습니다
ANSI_ESCAPE   = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# C0·C1 제어문자, 그리고 글자 방향을 뒤집어 파일명을 위장하는 문자(U+202E 등)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def safe_path(path: str) -> str:
    """파일 경로를 화면에 찍기 전에 제어문자를 제거합니다."""
    return CONTROL_CHARS.sub("", ANSI_ESCAPE.sub("", path))


log = logging.getLogger(__name__)


def setup_logging() -> None:
    """검사 이력을 로그 파일에 남깁니다.

    import 시점이 아니라 실행할 때 설정해야 --help 만 봐도 파일이 생기는 일이 없습니다.
    화면 출력은 print 가 맡고, 로그는 파일에만 씁니다. 파일별 기록까지 터미널에
    찍으면 파일 수만큼 줄이 쏟아져 정작 결과 보고서가 묻힙니다.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)s  %(message)s",
        handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
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
def collect_hashes(directory: str, exclude_dirs=()) -> tuple:
    """
    지정한 폴더 안의 모든 파일에 대해 해시를 계산합니다.

    반환값은 ({상대경로: 해시값}, {상대경로: 실패이유}) 두 개입니다.
    읽지 못한 파일을 조용히 건너뛰면 이후 비교에서 '삭제됨'으로 오판하게 되므로
    실패 목록을 따로 돌려주어 호출한 쪽이 판단하게 합니다.

    숨김 폴더도 기본으로 검사합니다. 보안 검사에서는 오히려 숨김 폴더에
    중요한 파일이 있을 수 있으므로, 제외는 exclude_dirs 로 명시해야 합니다.
    """
    hashes = {}
    errors = {}
    directory = os.path.abspath(directory)   # 절대 경로로 통일

    # 도구가 실제로 만든 파일만 경로로 판단해 제외합니다.
    # 이름만 보고 제외하면 사용자의 backup/snapshot.json 까지 검사에서 빠집니다.
    tool_files = (SNAPSHOT_FILE, SNAPSHOT_FILE + ".tmp", LOG_FILE, KEY_FILE)
    tool_paths = {os.path.realpath(p) for p in tool_files}

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
            if os.path.realpath(filepath) in tool_paths:
                continue

            # 폴더 경로를 제거한 상대 경로를 키로 사용
            relative_path = os.path.relpath(filepath, directory)

            try:
                hashes[relative_path] = fingerprint(filepath)
                log.info(f"  해시 계산 완료: {safe_path(relative_path)}")
            except OSError as e:
                errors[relative_path] = str(e)
                log.error(f"  검사 실패: {safe_path(relative_path)} → {e}")

    return hashes, errors


def is_unverifiable(path: str, errors: dict) -> bool:
    """path 자체를, 또는 path 가 들어 있는 폴더를 읽지 못했는지 확인합니다."""
    return any(
        path == failed or failed == "." or path.startswith(failed + os.sep)
        for failed in errors
    )


# ─────────────────────────────────────────
# 핵심 함수 3: 스냅샷 서명 (위변조 방지)
# ─────────────────────────────────────────
def load_or_create_key() -> str:
    """
    스냅샷 서명용 비밀키를 불러오거나, 없으면 새로 만듭니다.

    공격자가 파일을 바꾼 뒤 snapshot.json까지 함께 조작하면
    해시 비교만으로는 탐지할 수 없습니다.
    비밀키로 스냅샷에 서명해 두면 스냅샷 자체의 위변조를 잡아낼 수 있습니다.
    (단, 키 파일이 유출되면 무력화되므로 안전한 곳에 보관해야 합니다.)
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
        # 빈 키로 서명하면 누구나 같은 서명을 만들 수 있습니다
        if not key:
            raise ValueError(f"비밀키 파일({KEY_FILE})이 비어 있습니다")
        return key

    key = secrets.token_hex(32)   # 256비트 무작위 키
    # 처음부터 소유자 전용 권한(600)으로 만듭니다. 일반 권한으로 만든 뒤 바꾸면
    # 그 사이 잠깐 같은 컴퓨터의 다른 사용자가 키를 읽을 수 있습니다.
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    log.info(f"  서명용 비밀키 생성: {KEY_FILE}")
    return key


def load_key_or_report() -> str | None:
    """키를 불러오고, 실패하면 이유를 보여준 뒤 None 을 돌려줍니다."""
    try:
        return load_or_create_key()
    except (OSError, ValueError) as e:
        print(f"\n❌ 비밀키를 사용할 수 없습니다: {e}")
        print(f"   {KEY_FILE} 를 확인해 주세요.\n")
        log.error(f"  비밀키 사용 불가: {e}")
        return None


def compute_signature(snapshot_data: dict, key: str) -> str:
    """
    스냅샷 내용 전체에 대한 HMAC-SHA256 서명을 계산합니다.
    signature 필드 자체는 계산에서 제외합니다.
    """
    payload = {k: v for k, v in snapshot_data.items() if k != "signature"}
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


# ─────────────────────────────────────────
# 기능 A: 스냅샷 저장
# ─────────────────────────────────────────
def create_snapshot(directory: str, exclude_dirs=()) -> int:
    """
    현재 상태(해시 딕셔너리)를 snapshot.json에 저장합니다.
    이것이 나중에 비교할 '기준선(baseline)'이 됩니다.
    """
    if not os.path.isdir(directory):
        print(f"\n❌ 폴더를 찾을 수 없습니다: {safe_path(directory)}")
        print("   경로를 다시 확인해 주세요.\n")
        return EXIT_USAGE_ERROR

    log.info(f"=== 스냅샷 생성 시작: {directory} ===")
    hashes, errors = collect_hashes(directory, exclude_dirs)

    # 일부를 읽지 못한 상태로 기준선을 만들면 이후 검증 결과를 신뢰할 수 없습니다
    if errors:
        print(f"\n❌ 검사하지 못한 파일·폴더가 {len(errors)}개 있어 스냅샷을 만들지 않았습니다.")
        for path, reason in errors.items():
            print(f"   • {safe_path(path)} → {safe_path(reason)}")
        print("   권한을 확인한 뒤 다시 시도해 주세요.\n")
        log.error(f"=== 스냅샷 중단: 검사 실패 {len(errors)}건 ===")
        return EXIT_SCAN_INCOMPLETE

    snapshot_data = {
        "created_at": datetime.now().isoformat(),
        "target_directory": os.path.abspath(directory),
        # 제외 설정도 서명 대상에 넣습니다. 검증 때 몰래 다른 폴더를 빼서
        # 그 안의 변조를 숨기는 것을 막기 위해서입니다.
        "exclude_dirs": sorted(exclude_dirs),
        "file_count": len(hashes),
        "files": hashes
    }

    # 스냅샷 자체의 위변조를 막기 위해 비밀키로 서명
    key = load_key_or_report()
    if key is None:
        return EXIT_VERIFICATION_FAILED
    snapshot_data["signature"] = compute_signature(snapshot_data, key)

    # 임시 파일에 다 쓴 뒤 한 번에 바꿔치기합니다. 기존 파일에 바로 쓰다가
    # 디스크가 차거나 중단되면 하나뿐인 기준선이 반쯤 쓰인 채 망가집니다.
    temp_file = SNAPSHOT_FILE + ".tmp"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, SNAPSHOT_FILE)
    except OSError as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        print(f"\n❌ 스냅샷을 저장하지 못했습니다: {e}")
        print("   이전 스냅샷이 있었다면 그대로 남아 있습니다.\n")
        log.error(f"=== 스냅샷 저장 실패: {e} ===")
        return EXIT_USAGE_ERROR

    log.info(f"=== 스냅샷 완료: {len(hashes)}개 파일 → {SNAPSHOT_FILE} ===")
    print(f"\n✅ 스냅샷 저장 완료: {len(hashes)}개 파일이 기록되었습니다.")
    return EXIT_OK


# ─────────────────────────────────────────
# 기능 B: 무결성 검증
# ─────────────────────────────────────────
def verify_integrity(directory: str, exclude_dirs=None, allow_unsigned: bool = False) -> int:
    """
    현재 상태와 스냅샷을 비교해 변조/추가/삭제된 파일을 탐지합니다.
    이것이 디지털 포렌식의 핵심 개념입니다!

    서명을 확인할 수 없으면 기본적으로 검증을 중단합니다(fail-closed).
    검증할 수 없는데 "무결성이 확인되었다"고 말하는 것이 가장 위험하기 때문입니다.

    exclude_dirs 를 생략하면 스냅샷에 기록된 제외 설정을 그대로 씁니다.
    다른 값을 주면 거부합니다.
    """
    # 스냅샷 파일이 없으면 안내
    if not os.path.exists(SNAPSHOT_FILE):
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})이 없습니다.")
        print("   먼저 --snapshot 옵션으로 기준선을 만들어 주세요.\n")
        return EXIT_USAGE_ERROR

    if not os.path.isdir(directory):
        print(f"\n❌ 폴더를 찾을 수 없습니다: {safe_path(directory)}")
        print("   경로를 다시 확인해 주세요.\n")
        return EXIT_USAGE_ERROR

    # 저장된 스냅샷 불러오기
    # ValueError: 깨진 JSON, UTF-8 이 아닌 바이트 / OSError: 읽기 권한 없음 등
    try:
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            snapshot_data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})을 읽을 수 없습니다: {safe_path(str(e))}")
        print("   손상되었다면 --snapshot 옵션으로 다시 생성해 주세요.\n")
        return EXIT_VERIFICATION_FAILED

    # JSON은 유효해도 스냅샷 형식이 아니면 안내
    recorded_excludes = (snapshot_data.get("exclude_dirs", [])
                         if isinstance(snapshot_data, dict) else None)
    if (not isinstance(snapshot_data, dict)
            or not isinstance(snapshot_data.get("files"), dict)
            or not isinstance(recorded_excludes, list)
            or not all(isinstance(d, str) for d in recorded_excludes)):
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})의 형식이 올바르지 않습니다.")
        print("   --snapshot 옵션으로 다시 생성해 주세요.\n")
        return EXIT_VERIFICATION_FAILED

    # 스냅샷 자체가 위변조되지 않았는지 서명 확인
    signature = snapshot_data.get("signature")
    if signature is None or not os.path.exists(KEY_FILE):
        reason = ("서명이 없는 스냅샷입니다 (구버전에서 생성)" if signature is None
                  else f"비밀키 파일({KEY_FILE})이 없습니다")
        if not allow_unsigned:
            print(f"\n🚨 검증을 중단합니다: {reason}.")
            print("   스냅샷 자체의 위변조 여부를 확인할 수 없어 결과를 신뢰할 수 없습니다.")
            print("   --snapshot 으로 기준선을 다시 만들거나,")
            print("   위험을 감수하고 진행하려면 --allow-unsigned 를 명시해 주세요.\n")
            log.error(f"  서명 검증 불가({reason}) - 검증 중단")
            return EXIT_VERIFICATION_FAILED
        print(f"\n⚠️  주의: {reason}. --allow-unsigned 지정으로 검증을 계속합니다.")
        print("   스냅샷 자체의 위변조 여부는 확인되지 않았습니다.")
        log.warning(f"  서명 검증 생략({reason}) - allow_unsigned")
    else:
        key = load_key_or_report()
        if key is None:
            return EXIT_VERIFICATION_FAILED
        expected = compute_signature(snapshot_data, key)
        # 서명값은 조작될 수 있는 입력이므로 문자열인지부터 확인합니다.
        # bytes 로 비교해야 ASCII 가 아닌 글자가 섞여도 예외 없이 '불일치'로 처리됩니다.
        valid = (isinstance(signature, str)
                 and hmac.compare_digest(expected.encode(), signature.encode("utf-8")))
        if not valid:
            print(f"\n🚨 경고: 스냅샷 파일({SNAPSHOT_FILE})의 서명이 일치하지 않습니다!")
            print("   스냅샷 자체가 위변조되었을 가능성이 있어 검증을 중단합니다.")
            print("   신뢰할 수 있는 기준선이 필요하면 --snapshot 으로 다시 생성해 주세요.\n")
            log.error("  스냅샷 서명 불일치 - 위변조 의심, 검증 중단")
            return EXIT_VERIFICATION_FAILED

    # 제외 설정은 스냅샷(서명으로 보호됨)에 기록된 것을 기준으로 합니다
    if exclude_dirs is not None and set(exclude_dirs) != set(recorded_excludes):
        def describe(dirs):
            return ", ".join(safe_path(d) for d in sorted(dirs)) or "없음"
        print("\n❌ 제외 설정이 스냅샷과 다릅니다.")
        print(f"   스냅샷: {describe(recorded_excludes)} / 지금: {describe(exclude_dirs)}")
        print("   --exclude 를 생략하면 스냅샷에 기록된 설정을 그대로 사용합니다.\n")
        log.error("  제외 설정 불일치 - 검증 중단")
        return EXIT_USAGE_ERROR
    exclude_dirs = set(recorded_excludes)

    log.info(f"=== 무결성 검증 시작: {directory} ===")

    old_hashes = snapshot_data["files"]
    # 스냅샷에서 읽은 값은 화면에 찍기 전에 정제합니다 (--allow-unsigned 면 조작됐을 수 있음)
    created_at = safe_path(str(snapshot_data.get("created_at", "알 수 없음")))

    # 검증 대상 폴더가 스냅샷 생성 당시 폴더와 다르면 경고
    baseline_dir = snapshot_data.get("target_directory")
    if baseline_dir and os.path.abspath(directory) != baseline_dir:
        print(f"\n⚠️  주의: 스냅샷은 '{safe_path(str(baseline_dir))}' 폴더 기준으로 생성되었습니다.")
        print(f"   현재 검증 대상('{safe_path(os.path.abspath(directory))}')과 다릅니다. 결과 해석에 유의하세요.")
        log.warning(f"  대상 폴더 불일치 - 스냅샷: {baseline_dir} / 검증: {os.path.abspath(directory)}")

    # 현재 상태의 해시 계산
    current_hashes, scan_errors = collect_hashes(directory, exclude_dirs)

    # ── 비교 시작 ──────────────────────────
    modified = []   # 내용이 바뀐 파일
    deleted  = []   # 삭제된 파일
    added    = []   # 새로 생긴 파일

    # 기존 파일 검사
    for filepath, old_hash in old_hashes.items():
        # 읽지 못한 파일(또는 읽지 못한 폴더 안의 파일)은 '삭제'가 아니라 '검사 실패'입니다.
        # 둘을 섞으면 멀쩡히 있는 파일을 삭제됐다고 보고하게 됩니다.
        if is_unverifiable(filepath, scan_errors):
            continue
        if filepath not in current_hashes:
            deleted.append(filepath)
            log.warning(f"  [삭제] {safe_path(filepath)}")
        elif current_hashes[filepath] != old_hash:
            modified.append(filepath)
            log.warning(f"  [변조] {safe_path(filepath)}")

    # 새로 생긴 파일 검사
    for filepath in current_hashes:
        if filepath not in old_hashes:
            added.append(filepath)
            log.info(f"  [추가] {safe_path(filepath)}")

    # ── 보고서 출력 ──────────────────────
    print("\n" + "="*50)
    print("    📋 무결성 검사 결과 보고서")
    print("="*50)
    print(f"  스냅샷 기준 시각: {created_at}")
    print(f"  검사 완료 시각:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  검사 파일 수:     {len(current_hashes)}개")
    print("-"*50)

    if modified:
        print(f"\n⚠️  변조된 파일 ({len(modified)}개):")
        for f in modified:
            print(f"   • {safe_path(f)}")
    else:
        print("\n✅ 변조된 파일: 없음")

    if deleted:
        print(f"\n🗑️  삭제된 파일 ({len(deleted)}개):")
        for f in deleted:
            print(f"   • {safe_path(f)}")
    else:
        print("✅ 삭제된 파일: 없음")

    if added:
        print(f"\n📄 새로 추가된 파일 ({len(added)}개):")
        for f in added:
            print(f"   • {safe_path(f)}")
    else:
        print("✅ 새로 추가된 파일: 없음")

    if scan_errors:
        print(f"\n❓ 검사하지 못한 파일·폴더 ({len(scan_errors)}개):")
        for f, reason in scan_errors.items():
            print(f"   • {safe_path(f)} → {safe_path(reason)}")

    print("="*50)

    total = len(modified) + len(deleted) + len(added)

    if scan_errors:
        # 일부를 확인하지 못했으므로 '이상 없음'이라고 단언할 수 없습니다
        print(f"\n⚠️  검사하지 못한 파일·폴더가 {len(scan_errors)}개 있어 결과를 확정할 수 없습니다.")
        if total:
            print(f"   확인된 변경은 {total}건입니다.")
        print()
    elif total == 0:
        print("\n🎉 모든 파일의 무결성이 확인되었습니다!\n")
    else:
        print(f"\n🚨 총 {total}건의 변경이 감지되었습니다. 로그를 확인하세요.\n")

    log.info(
        f"=== 검증 완료: 변조 {len(modified)}건, 삭제 {len(deleted)}건, "
        f"추가 {len(added)}건, 검사실패 {len(scan_errors)}건 ==="
    )

    if scan_errors:
        return EXIT_SCAN_INCOMPLETE
    return EXIT_CHANGES_DETECTED if total else EXIT_OK


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
    parser.add_argument("--allow-unsigned", action="store_true",
                        help="서명이나 비밀키가 없어도 검증을 진행합니다 (신뢰도가 낮아집니다).")

    args = parser.parse_args()
    setup_logging()

    if args.snapshot:
        return create_snapshot(args.snapshot, set(args.exclude))
    if args.verify:
        return verify_integrity(args.verify, set(args.exclude) if args.exclude else None,
                                args.allow_unsigned)

    parser.print_help()
    return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
