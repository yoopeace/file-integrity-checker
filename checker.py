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
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def safe_path(path: str) -> str:
    """파일 경로를 화면에 찍기 전에 제어문자를 제거합니다."""
    return CONTROL_CHARS.sub("", ANSI_ESCAPE.sub("", path))

# 로그 설정: 파일과 터미널 동시 출력
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


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
    tool_paths = {os.path.realpath(p) for p in (SNAPSHOT_FILE, LOG_FILE, KEY_FILE)}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for filename in files:
            filepath = os.path.join(root, filename)
            if os.path.realpath(filepath) in tool_paths:
                continue

            # 폴더 경로를 제거한 상대 경로를 키로 사용
            relative_path = os.path.relpath(filepath, directory)

            try:
                file_hash = calculate_hash(filepath)
                hashes[relative_path] = file_hash
                log.info(f"  해시 계산 완료: {safe_path(relative_path)}")
            except OSError as e:
                errors[relative_path] = str(e)
                log.error(f"  검사 실패: {safe_path(relative_path)} → {e}")

    return hashes, errors


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
            return f.read().strip()

    key = secrets.token_hex(32)   # 256비트 무작위 키
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    # 소유자만 읽고 쓸 수 있게 제한합니다. 기본 권한(644)이면 같은 컴퓨터의
    # 다른 사용자가 키를 읽어 서명을 위조할 수 있습니다.
    os.chmod(KEY_FILE, 0o600)
    log.info(f"  서명용 비밀키 생성: {KEY_FILE}")
    return key


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
        print(f"\n❌ 검사하지 못한 파일이 {len(errors)}개 있어 스냅샷을 만들지 않았습니다.")
        for path, reason in errors.items():
            print(f"   • {safe_path(path)} → {reason}")
        print("   권한을 확인한 뒤 다시 시도해 주세요.\n")
        log.error(f"=== 스냅샷 중단: 검사 실패 {len(errors)}건 ===")
        return EXIT_SCAN_INCOMPLETE

    snapshot_data = {
        "created_at": datetime.now().isoformat(),
        "target_directory": os.path.abspath(directory),
        "file_count": len(hashes),
        "files": hashes
    }

    # 스냅샷 자체의 위변조를 막기 위해 비밀키로 서명
    key = load_or_create_key()
    snapshot_data["signature"] = compute_signature(snapshot_data, key)

    with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
        json.dump(snapshot_data, f, ensure_ascii=False, indent=2)

    log.info(f"=== 스냅샷 완료: {len(hashes)}개 파일 → {SNAPSHOT_FILE} ===")
    print(f"\n✅ 스냅샷 저장 완료: {len(hashes)}개 파일이 기록되었습니다.")
    return EXIT_OK


# ─────────────────────────────────────────
# 기능 B: 무결성 검증
# ─────────────────────────────────────────
def verify_integrity(directory: str, exclude_dirs=(), allow_unsigned: bool = False) -> int:
    """
    현재 상태와 스냅샷을 비교해 변조/추가/삭제된 파일을 탐지합니다.
    이것이 디지털 포렌식의 핵심 개념입니다!

    서명을 확인할 수 없으면 기본적으로 검증을 중단합니다(fail-closed).
    검증할 수 없는데 "무결성이 확인되었다"고 말하는 것이 가장 위험하기 때문입니다.
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
    try:
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            snapshot_data = json.load(f)
    except json.JSONDecodeError:
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})이 손상되어 읽을 수 없습니다.")
        print("   --snapshot 옵션으로 다시 생성해 주세요.\n")
        return EXIT_VERIFICATION_FAILED

    # JSON은 유효해도 스냅샷 형식이 아니면 안내
    if not isinstance(snapshot_data, dict) or not isinstance(snapshot_data.get("files"), dict):
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
        key = load_or_create_key()
        expected = compute_signature(snapshot_data, key)
        if not hmac.compare_digest(expected, signature):
            print(f"\n🚨 경고: 스냅샷 파일({SNAPSHOT_FILE})의 서명이 일치하지 않습니다!")
            print("   스냅샷 자체가 위변조되었을 가능성이 있어 검증을 중단합니다.")
            print("   신뢰할 수 있는 기준선이 필요하면 --snapshot 으로 다시 생성해 주세요.\n")
            log.error("  스냅샷 서명 불일치 - 위변조 의심, 검증 중단")
            return EXIT_VERIFICATION_FAILED

    log.info(f"=== 무결성 검증 시작: {directory} ===")

    old_hashes = snapshot_data["files"]
    created_at  = snapshot_data.get("created_at", "알 수 없음")

    # 검증 대상 폴더가 스냅샷 생성 당시 폴더와 다르면 경고
    baseline_dir = snapshot_data.get("target_directory")
    if baseline_dir and os.path.abspath(directory) != baseline_dir:
        print(f"\n⚠️  주의: 스냅샷은 '{baseline_dir}' 폴더 기준으로 생성되었습니다.")
        print(f"   현재 검증 대상('{os.path.abspath(directory)}')과 다릅니다. 결과 해석에 유의하세요.")
        log.warning(f"  대상 폴더 불일치 - 스냅샷: {baseline_dir} / 검증: {os.path.abspath(directory)}")

    # 현재 상태의 해시 계산
    current_hashes, scan_errors = collect_hashes(directory, exclude_dirs)

    # ── 비교 시작 ──────────────────────────
    modified = []   # 내용이 바뀐 파일
    deleted  = []   # 삭제된 파일
    added    = []   # 새로 생긴 파일

    # 기존 파일 검사
    for filepath, old_hash in old_hashes.items():
        # 읽지 못한 파일은 '삭제'가 아니라 '검사 실패'입니다.
        # 둘을 섞으면 멀쩡히 있는 파일을 삭제됐다고 보고하게 됩니다.
        if filepath in scan_errors:
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
        print(f"\n❓ 검사하지 못한 파일 ({len(scan_errors)}개):")
        for f, reason in scan_errors.items():
            print(f"   • {safe_path(f)} → {reason}")

    print("="*50)

    total = len(modified) + len(deleted) + len(added)

    if scan_errors:
        # 일부를 확인하지 못했으므로 '이상 없음'이라고 단언할 수 없습니다
        print(f"\n⚠️  검사하지 못한 파일이 {len(scan_errors)}개 있어 결과를 확정할 수 없습니다.")
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
                        help="검사에서 제외할 폴더 이름 (여러 번 지정 가능, 예: --exclude .git)")
    parser.add_argument("--allow-unsigned", action="store_true",
                        help="서명이나 비밀키가 없어도 검증을 진행합니다 (신뢰도가 낮아집니다).")

    args = parser.parse_args()
    exclude_dirs = set(args.exclude)

    if args.snapshot:
        return create_snapshot(args.snapshot, exclude_dirs)
    if args.verify:
        return verify_integrity(args.verify, exclude_dirs, args.allow_unsigned)

    parser.print_help()
    return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
