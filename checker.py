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
import json         # 스냅샷 저장/불러오기
import os           # 파일/폴더 탐색
import argparse     # 터미널 명령줄 옵션 처리
import logging      # 로그 파일 기록
from datetime import datetime  # 날짜/시간 기록

# ─────────────────────────────────────────
# 설정값 (원하면 바꿔도 됩니다)
# ─────────────────────────────────────────
SNAPSHOT_FILE = "snapshot.json"       # 해시 저장 파일 이름
LOG_FILE      = "integrity_log.txt"   # 로그 파일 이름

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
def collect_hashes(directory: str) -> dict:
    """
    지정한 폴더 안의 모든 파일에 대해 해시를 계산하고
    {상대경로: 해시값} 딕셔너리를 반환합니다.
    """
    hashes = {}
    directory = os.path.abspath(directory)   # 절대 경로로 통일

    for root, dirs, files in os.walk(directory):
        # 숨김 폴더(.git 등)는 건너뜁니다
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            # 스냅샷/로그 파일 자체는 제외
            if filename in (SNAPSHOT_FILE, LOG_FILE):
                continue

            filepath = os.path.join(root, filename)
            # 폴더 경로를 제거한 상대 경로를 키로 사용
            relative_path = os.path.relpath(filepath, directory)

            try:
                file_hash = calculate_hash(filepath)
                hashes[relative_path] = file_hash
                log.info(f"  해시 계산 완료: {relative_path}")
            except PermissionError:
                log.warning(f"  권한 없음 (건너뜀): {relative_path}")
            except Exception as e:
                log.error(f"  오류 발생: {relative_path} → {e}")

    return hashes


# ─────────────────────────────────────────
# 기능 A: 스냅샷 저장
# ─────────────────────────────────────────
def create_snapshot(directory: str) -> None:
    """
    현재 상태(해시 딕셔너리)를 snapshot.json에 저장합니다.
    이것이 나중에 비교할 '기준선(baseline)'이 됩니다.
    """
    if not os.path.isdir(directory):
        print(f"\n❌ 폴더를 찾을 수 없습니다: {directory}")
        print("   경로를 다시 확인해 주세요.\n")
        return

    log.info(f"=== 스냅샷 생성 시작: {directory} ===")
    hashes = collect_hashes(directory)

    snapshot_data = {
        "created_at": datetime.now().isoformat(),
        "target_directory": os.path.abspath(directory),
        "file_count": len(hashes),
        "files": hashes
    }

    with open(SNAPSHOT_FILE, "w", encoding="utf-8") as f:
        json.dump(snapshot_data, f, ensure_ascii=False, indent=2)

    log.info(f"=== 스냅샷 완료: {len(hashes)}개 파일 → {SNAPSHOT_FILE} ===")
    print(f"\n✅ 스냅샷 저장 완료: {len(hashes)}개 파일이 기록되었습니다.")


# ─────────────────────────────────────────
# 기능 B: 무결성 검증
# ─────────────────────────────────────────
def verify_integrity(directory: str) -> None:
    """
    현재 상태와 스냅샷을 비교해 변조/추가/삭제된 파일을 탐지합니다.
    이것이 디지털 포렌식의 핵심 개념입니다!
    """
    # 스냅샷 파일이 없으면 안내
    if not os.path.exists(SNAPSHOT_FILE):
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})이 없습니다.")
        print("   먼저 --snapshot 옵션으로 기준선을 만들어 주세요.\n")
        return

    if not os.path.isdir(directory):
        print(f"\n❌ 폴더를 찾을 수 없습니다: {directory}")
        print("   경로를 다시 확인해 주세요.\n")
        return

    # 저장된 스냅샷 불러오기
    try:
        with open(SNAPSHOT_FILE, "r", encoding="utf-8") as f:
            snapshot_data = json.load(f)
    except json.JSONDecodeError:
        print(f"\n❌ 스냅샷 파일({SNAPSHOT_FILE})이 손상되어 읽을 수 없습니다.")
        print("   --snapshot 옵션으로 다시 생성해 주세요.\n")
        return

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
    current_hashes = collect_hashes(directory)

    # ── 비교 시작 ──────────────────────────
    modified = []   # 내용이 바뀐 파일
    deleted  = []   # 삭제된 파일
    added    = []   # 새로 생긴 파일

    # 기존 파일 검사
    for filepath, old_hash in old_hashes.items():
        if filepath not in current_hashes:
            deleted.append(filepath)
            log.warning(f"  [삭제] {filepath}")
        elif current_hashes[filepath] != old_hash:
            modified.append(filepath)
            log.warning(f"  [변조] {filepath}")

    # 새로 생긴 파일 검사
    for filepath in current_hashes:
        if filepath not in old_hashes:
            added.append(filepath)
            log.info(f"  [추가] {filepath}")

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
            print(f"   • {f}")
    else:
        print("\n✅ 변조된 파일: 없음")

    if deleted:
        print(f"\n🗑️  삭제된 파일 ({len(deleted)}개):")
        for f in deleted:
            print(f"   • {f}")
    else:
        print("✅ 삭제된 파일: 없음")

    if added:
        print(f"\n📄 새로 추가된 파일 ({len(added)}개):")
        for f in added:
            print(f"   • {f}")
    else:
        print("✅ 새로 추가된 파일: 없음")

    print("="*50)

    if not modified and not deleted and not added:
        print("\n🎉 모든 파일의 무결성이 확인되었습니다!\n")
    else:
        total = len(modified) + len(deleted) + len(added)
        print(f"\n🚨 총 {total}건의 변경이 감지되었습니다. 로그를 확인하세요.\n")

    log.info(f"=== 검증 완료: 변조 {len(modified)}건, 삭제 {len(deleted)}건, 추가 {len(added)}건 ===")


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

    args = parser.parse_args()

    if args.snapshot:
        create_snapshot(args.snapshot)
    elif args.verify:
        verify_integrity(args.verify)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
