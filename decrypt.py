#!/usr/bin/env python3
"""
IKA9nt.Encrypter  一键批量解密脚本
=====================================
用法:
  1. 把本脚本放到 StreamingAssets/StandaloneWindows64/ 同级目录
     或者用 --dir 参数指定 bundle 所在文件夹

  pip install pycryptodome
  python decrypt_all.py                         # 解密当前目录所有已知文件
  python decrypt_all.py --dir path/to/bundles   # 指定目录
  python decrypt_all.py --dir path/to/bundles --outdir path/to/output
"""

import sys, struct, hashlib, argparse
from pathlib import Path

# ─────────────────────────────────────────────────────
# passCharacter (195字符, 来自 stringliteral.json 0x2B39428)
# 注意: FF80-FF84 (ﾀﾁﾂﾃﾄ) 不在此列表中!
# ─────────────────────────────────────────────────────
PASS_CHAR = (
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをん'
    'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'
    'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿ'       # FF71-FF7F (15字)
    'ﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ'  # FF85-FF9D, FF66 (25字)
)
assert len(PASS_CHAR) == 195, f"passCharacter length error: {len(PASS_CHAR)}"

GUID = "f94ef3020dd748e9a3489b702cd842a0"
L = 195

# ─────────────────────────────────────────────────────
# PasswordMap.ctor 中硬编码的索引 → 解码后的密码
# ─────────────────────────────────────────────────────
def _decode_indices(indices):
    result = []
    for i, idx in enumerate(indices):
        shift = int(GUID[i % 32], 16)
        actual = idx - shift
        if actual < 0:
            actual += L
        result.append(PASS_CHAR[actual])
    return ''.join(result)

_MAP_PASSWORDS = {
    'common':              _decode_indices([0xba,0x0b,0x6d,0xb6,0x7f,0xc5,0x54,0x43,0x4a,0xaf,
                                            0x72,0x29,0x3a,0x28,0xc8,0x4d,0x34,0x20,0x16,0x88,0xbd]),
    'commonr18':           _decode_indices([0xa3,0xa9,0x10,0xcd,0x22,0xad,0x5b,0x9f,0x7e,0x80,
                                            0x88,0x94,0x73,0x15,0x15,0xae,0x21,0xad,0x69,0xc2,
                                            0x2a,0x9f,0x3b,0xa0,0x06,0x6d,0xb4]),
    'sceneresourcestitle': _decode_indices([0x59,0xc7,0x69,0x25,0xad,0x0f,0x5d,0x2c,0x92,0x15,
                                            0xba,0xb8,0x65,0x98,0xc8,0x22,0x39,0x23,0x09,0x45,
                                            0x9c,0x85,0x2a,0x99,0x64,0xc2,0x65,0xa9]),
    'Vol1':                _decode_indices([0xb9,0x36,0x43,0x3a,0x6e,0x34,0x7e,0x24,0x84,0x72,
                                            0x49,0x09,0x3f,0xb7,0xc7,0x3b,0xb3,0xb3,0x77,0x7b,
                                            0x31,0x5d,0x67,0x00,0x7e,0x9c]),
    'DLC':                 _decode_indices([0xa5,0x47,0x91,0xa3,0x99,0xa3,0xa6,0x9c,0x20,0xc4,
                                            0xbf,0x86,0x77,0xb5,0x88,0x79,0x83,0x8a,0x66,0x5c,
                                            0x6b,0x3d,0x33,0x5a,0x27,0x83,0x3d]),
}

# ─────────────────────────────────────────────────────
# 所有已知文件: hash → (label, password)
# salt = str(hash).encode('utf-8')
# ─────────────────────────────────────────────────────
KNOWN_FILES = {
    # ── reference bundles (EncrypterKeyData.reference) ──
    -1441731759: ('common',              _MAP_PASSWORDS['common']),
    -1651898362: ('commonr18',           _MAP_PASSWORDS['commonr18']),
     66086011:   ('sceneresourcestitle', _MAP_PASSWORDS['sceneresourcestitle']),

    # ── additional data manifest files ──
    -1488405969: ('Vol1_manifest',       _MAP_PASSWORDS['Vol1']),
     1582260102: ('DLC_manifest',        _MAP_PASSWORDS['DLC']),

    # ── extrapatch bundles (密码来自 Vol1 manifest) ──
    -368474238:  ('extrapatch_debug',         'ソ8んｲUえﾗｵFGニセｽヒDqミﾌdｻこノmﾆナソゆ'),
    -1211565434: ('extrapatch_freecamera',    'cdヤｦxﾋ0エすﾘへカﾗカはﾜVかホOｶﾘYo'),
    -1685771737: ('extrapatch_graphicextra',  'こてｷムまuやPロろサﾅYマｾnロヌﾘサあﾑくｾｿ'),
     174090861:  ('extrapatch_sylpheedequip', 'チOフかﾍロなｺlルXれやYいるソら1ﾊイヨゆLｿせスカf'),
     1128473344: ('extrapatch_zr7',           'EFレKﾉテヲSZｲ706うムﾙワヤ9あQクヘそｼﾓシ'),
     -943140464: ('extrapatch_idcard',        'メsｶｱｲuｱyｳsﾇTJLのmラハwﾍレﾐ'),
     1968047279: ('extrapatch_bundlestock',   'bfスｹむなTもムﾒｹみGｾちとTxb'),

    # ── DLC bundles (密码来自 DLC manifest) ──
    -1190432565: ('sceneresourcesvol1', 'むほｼxユE5pしJgとラハﾉむRｷeBﾇﾉミわｴのめみむモ2'),
}


def decrypt_data(cipherdata: bytes, password: str, hash_val: int) -> bytes:
    """
    AES-256 ECB keystream 解密.
    salt    = str(hash_val).encode('utf-8')
    key     = PBKDF2-SHA1(password.UTF8, salt, iterations=1000, dklen=32)
    block n = AES_ECB(key, pack('<q', n+1) + 8_zero_bytes)   XOR ciphertext
    """
    from Crypto.Cipher import AES
    salt = str(hash_val).encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), salt, 1000, dklen=32)
    ecb = AES.new(dk, AES.MODE_ECB)
    out = bytearray(len(cipherdata))
    for n in range((len(cipherdata) + 15) // 16):
        ks = ecb.encrypt(struct.pack('<q', n + 1) + b'\x00' * 8)
        s, e = n * 16, min((n + 1) * 16, len(cipherdata))
        for j in range(e - s):
            out[s + j] = cipherdata[s + j] ^ ks[j]
    return bytes(out)


def check_header(data: bytes) -> str:
    if data[:8] == b'UnityFS\x00':
        return '✓ UnityFS'
    if data[:5] == b'Unity':
        return '✓ Unity'
    # Detect text content (manifest files: ASCII label + tab + numbers + UTF-8 Japanese)
    try:
        preview = data.rstrip(b'\x00')[:80].decode('utf-8', errors='replace')
        # Good text: starts with ASCII word chars
        if preview and preview[0].isascii() and (preview[0].isalpha() or preview[0].isdigit()):
            short = preview[:50].replace('\t', ' ').replace('\r', '').replace('\n', '|')
            return f'✓ Text: {short!r}'
    except Exception:
        pass
    return f'? {data[:8].hex()}'


def decrypt_all(bundle_dir: Path, out_dir: Path):
    try:
        from Crypto.Cipher import AES  # noqa: just check
    except ImportError:
        print("[错误] 请先安装: pip install pycryptodome")
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    files_in_dir = {int(f.name): f for f in bundle_dir.iterdir()
                    if f.is_file() and f.name.lstrip('-').isdigit()}

    found     = [h for h in KNOWN_FILES if h in files_in_dir]
    unknown   = [h for h in files_in_dir if h not in KNOWN_FILES]
    not_found = [h for h in KNOWN_FILES if h not in files_in_dir]

    width = 76
    print("=" * width)
    print(f"  IKA9nt.Encrypter 批量解密")
    print(f"  输入目录: {bundle_dir}")
    print(f"  输出目录: {out_dir}")
    print(f"  找到已知文件: {len(found)}  /  未知文件: {len(unknown)}  /  缺失文件: {len(not_found)}")
    print("=" * width)

    ok_count = fail_count = 0

    for hash_val in sorted(found, key=abs):
        label, password = KNOWN_FILES[hash_val]
        src = files_in_dir[hash_val]
        dst = out_dir / f"{label}_{hash_val}.unity3d"

        size_mb = src.stat().st_size / 1024 / 1024
        print(f"  [{label}]  {hash_val}  ({size_mb:.1f} MB)  ...", end='', flush=True)

        try:
            data  = src.read_bytes()
            plain = decrypt_data(data, password, hash_val)
            dst.write_bytes(plain)
            status = check_header(plain)
            print(f"  {status}")
            if status.startswith('✓'):
                ok_count += 1
            else:
                fail_count += 1
        except Exception as e:
            print(f"  ✗ 错误: {e}")
            fail_count += 1

    if not_found:
        print()
        print("未找到(已删除或不存在):")
        for h in not_found:
            label, _ = KNOWN_FILES[h]
            print(f"  [{label}]  {h}")

    if unknown:
        print()
        print(f"未知文件 (不在已知列表中, 共 {len(unknown)} 个):")
        for h in sorted(unknown):
            print(f"  {h}  ({files_in_dir[h].stat().st_size:,} bytes)")

    print()
    print("=" * width)
    print(f"  完成!  成功: {ok_count}  失败/未知: {fail_count}")
    print("=" * width)


def main():
    ap = argparse.ArgumentParser(description='IKA9nt.Encrypter 一键批量解密')
    ap.add_argument('--dir',    default='.', help='bundle 文件所在目录 (默认: 当前目录)')
    ap.add_argument('--outdir', default=None, help='输出目录 (默认: <dir>/decrypted)')
    args = ap.parse_args()

    bundle_dir = Path(args.dir).resolve()
    out_dir    = Path(args.outdir).resolve() if args.outdir else bundle_dir / 'decrypted'

    if not bundle_dir.exists():
        print(f"[错误] 目录不存在: {bundle_dir}")
        sys.exit(1)

    decrypt_all(bundle_dir, out_dir)


if __name__ == '__main__':
    main()
