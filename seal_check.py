#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合同用印核查工具

用法:
    python seal_check.py 合同.pdf
    python seal_check.py 合同.pdf -o 输出目录 --dpi 400
    python seal_check.py 合同.pdf --json        # 额外输出机器可读结果

做四件事:
    1. 结构探测   —— 判定是电子签章还是扫描件
    2. 印章核查   —— 完整章（甲/乙方盖章处）+ 骑缝章（跨页连续性）
    3. 密码学验签 —— 用 openssl 验证 PKCS#7，证明签署后未被篡改
    4. 对账       —— 正文「（盖章）」要求数 vs 实际印章数

依赖: PyMuPDF, Pillow, NumPy；密码学部分需要 openssl 可执行文件。
      缺少依赖时会给出明确的安装提示，不会静默失败。
"""

import argparse
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Windows 控制台默认 GBK，中文会乱码
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

VERSION = '1.0.0'

# 印章判定阈值（可被命令行覆盖）
SEAM_MAX_WIDTH_PT = 40.0   # 窄于此视为骑缝切片（完整公章约 40mm ≈ 113pt）
FULL_MIN_WIDTH_PT = 60.0   # 宽于此视为完整印章
EDGE_TOL_PT = 2.0          # 判定「贴合页边」的容差


# ────────────────────────────── 输出helper ──────────────────────────────
class Log:
    def __init__(self, quiet=False):
        self.quiet = quiet
        self.lines = []

    def __call__(self, msg=''):
        self.lines.append(msg)
        if not self.quiet:
            print(msg)

    def head(self, title, ch='='):
        self(ch * 72)
        self(title)
        self(ch * 72)

    def save(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.lines))


# ────────────────────────────── 依赖检查 ──────────────────────────────
def preflight(log):
    """返回 (deps_ok, openssl_path)。缺依赖时给出安装指引。"""
    missing = []
    try:
        import fitz  # noqa
    except ImportError:
        missing.append(('PyMuPDF', 'pip install pymupdf'))
    try:
        from PIL import Image  # noqa
    except ImportError:
        missing.append(('Pillow', 'pip install pillow'))
    try:
        import numpy  # noqa
    except ImportError:
        missing.append(('NumPy', 'pip install numpy'))

    if missing:
        log('缺少 Python 依赖，无法运行：')
        for name, cmd in missing:
            log(f'  ✗ {name:<12} 请执行: {cmd}')
        log('')
        log('一次性装齐:  pip install pymupdf pillow numpy')
        return False, None

    openssl = find_openssl()
    if openssl:
        log(f'依赖检查  : PyMuPDF / Pillow / NumPy 就绪')
        log(f'OpenSSL   : {openssl}')
    else:
        log(f'依赖检查  : PyMuPDF / Pillow / NumPy 就绪')
        log('OpenSSL   : 未找到 —— 将跳过密码学验签（其余检查仍可进行）')
        log('            安装方式: Windows 装 Git for Windows 自带；'
            'Linux/macOS 通常已有；或用 --openssl 指定路径')
    return True, openssl


def find_openssl(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    p = shutil.which('openssl')
    if p:
        return p
    candidates = [
        r'C:\Program Files\Git\usr\bin\openssl.exe',
        r'C:\Program Files\Git\mingw64\bin\openssl.exe',
        r'C:\Program Files (x86)\Git\usr\bin\openssl.exe',
        '/usr/bin/openssl',
        '/usr/local/bin/openssl',
        '/opt/homebrew/bin/openssl',
    ]
    # Conda / 独立 Python 环境常见的自带 openssl
    for base in (sys.prefix, os.path.dirname(sys.executable)):
        if not base:
            continue
        candidates.append(os.path.join(base, 'Library', 'bin', 'openssl.exe'))
        candidates.append(os.path.join(base, 'bin', 'openssl'))
        candidates.append(os.path.join(base, '..', 'Library', 'bin', 'openssl.exe'))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


# ────────────────────────────── 结构探测 ──────────────────────────────
def probe_structure(doc, log):
    info = {
        'pages': doc.page_count,
        'metadata': doc.metadata or {},
        'is_encrypted': doc.is_encrypted,
        'sig_flags': doc.get_sigflags(),
        'widgets': [],
        'text_chars': 0,
    }
    for i, page in enumerate(doc):
        info['text_chars'] += len(page.get_text().strip())
        pr = page.rect
        for w in (page.widgets() or []):
            v = doc.xref_get_key(w.xref, 'V')
            vref = None
            if v and v[1] and v[1] != 'null':
                m = re.search(r'(\d+)\s+0\s+R', str(v[1]))
                vref = int(m.group(1)) if m else None
            r = w.rect
            info['widgets'].append({
                'page': i + 1, 'name': w.field_name, 'vref': vref, 'xref': w.xref,
                'x0': round(r.x0, 2), 'y0': round(r.y0, 2),
                'x1': round(r.x1, 2), 'y1': round(r.y1, 2),
                'w': round(r.width, 2), 'h': round(r.height, 2),
                'page_w': round(pr.width, 2), 'page_h': round(pr.height, 2),
            })

    md = info['metadata']
    producer = (md.get('producer') or '') + ' ' + (md.get('creator') or '')
    info['is_electronic'] = bool(info['widgets'])
    info['producer'] = producer.strip()

    log.head('一、文件结构')
    log(f'  页数          : {info["pages"]}')
    log(f'  Producer      : {md.get("producer", "(空)")}')
    log(f'  Creator       : {md.get("creator", "(空)")}')
    log(f'  加密          : {info["is_encrypted"]}')
    log(f'  文本字符数    : {info["text_chars"]:,}')
    log(f'  签名字段数    : {len(info["widgets"])}')
    if info['is_electronic']:
        log(f'  判定          : 电子签章 PDF（存在签章表单域）')
    elif info['text_chars'] > 200:
        log(f'  判定          : 原生文本 PDF，未见签章域 —— 印章可能是矢量图或图片')
    else:
        log(f'  判定          : 疑似扫描件（文本极少）')
    return info


# ────────────────────────────── 图像抽取 ──────────────────────────────
REF_RE = re.compile(r'/(\w+)\s+(\d+)\s+0\s+R')


def resolve_image(doc, obj_xref, depth=0):
    """从 AP/N 或 DR 出发，递归找到真正的图像 XObject xref。"""
    if obj_xref is None or depth > 6:
        return None
    st = doc.xref_get_key(obj_xref, 'Subtype')
    if st and st[1] and 'Image' in str(st[1]):
        return obj_xref
    txt = doc.xref_object(obj_xref, compressed=False) or ''
    for _, num in REF_RE.findall(txt):
        nx = int(num)
        if nx == obj_xref:
            continue
        st2 = doc.xref_get_key(nx, 'Subtype')
        if st2 and st2[1]:
            if 'Image' in str(st2[1]):
                return nx
            if 'Form' in str(st2[1]):
                got = resolve_image(doc, nx, depth + 1)
                if got:
                    return got
    return None


def widget_image(doc, widget_xref):
    ap = doc.xref_get_key(widget_xref, 'AP')
    target = None
    if ap and ap[1]:
        for _, num in REF_RE.findall(str(ap[1])):
            target = int(num)
            break
    return resolve_image(doc, target) if target else None


def pixmap_to_rgb(doc, xref):
    """取出图像并按 SMask 合成到白底，返回 PIL Image。"""
    import fitz
    from PIL import Image
    p = fitz.Pixmap(doc, xref)
    smask = None
    k = doc.xref_get_key(xref, 'SMask')
    if k and k[1] and 'null' not in str(k[1]):
        m = re.search(r'(\d+)\s+0\s+R', str(k[1]))
        if m:
            smask = int(m.group(1))

    # 若拿到的是 1 通道蒙版，反查引用它的彩色图
    if p.n == 1:
        owner = None
        for cand in range(1, doc.xref_length()):
            kk = doc.xref_get_key(cand, 'SMask')
            if kk and kk[1] and re.search(rf'\b{xref}\s+0\s+R', str(kk[1])):
                owner = cand
                break
        if owner:
            return pixmap_to_rgb(doc, owner)
        return Image.frombytes('L', (p.width, p.height), p.samples).convert('RGB')

    if p.n == 3:
        base = Image.frombytes('RGB', (p.width, p.height), p.samples)
    elif p.n == 4:
        base = Image.frombytes('RGBA', (p.width, p.height), p.samples).convert('RGB')
    elif p.n == 2:
        base = Image.frombytes('LA', (p.width, p.height), p.samples).convert('RGB')
    else:
        return None

    if smask:
        mp = fitz.Pixmap(doc, smask)
        if mp.n != 1:
            mp = fitz.Pixmap(fitz.csGRAY, mp)
        alpha = Image.frombytes('L', (mp.width, mp.height), mp.samples)
        if alpha.size != base.size:
            alpha = alpha.resize(base.size)
        white = Image.new('RGB', base.size, (255, 255, 255))
        white.paste(base, (0, 0), alpha)
        return white
    return base


# ────────────────────────────── 印章分类与核查 ──────────────────────────────
def is_flush_to_edge(w):
    """判断某个域是否贴合页面的左/右边缘（骑缝章的典型特征）。"""
    left_gap = w['x0']
    right_gap = w['page_w'] - w['x1']
    return (left_gap <= EDGE_TOL_PT) or (right_gap <= EDGE_TOL_PT)


def classify_widgets(widgets):
    """按签名者分组，并区分完整章 / 骑缝切片。"""
    groups = {}
    for w in widgets:
        key = w['vref'] if w['vref'] is not None else w['name'].split('_QF')[0]
        groups.setdefault(key, {'full': [], 'seam': []})
        named_seam = 'QF_EDGES' in w['name'] or 'QF' in w['name'].upper()
        thin = w['w'] <= SEAM_MAX_WIDTH_PT
        big = w['w'] >= FULL_MIN_WIDTH_PT
        if named_seam or (thin and is_flush_to_edge(w)):
            groups[key]['seam'].append(w)
        elif big:
            groups[key]['full'].append(w)
        else:
            groups[key]['seam' if thin else 'full'].append(w)
    return groups


def check_seals(doc, info, log, outdir):
    """返回 (seal_records, findings)。findings 为问题描述列表。"""
    import fitz
    from PIL import Image

    widgets = info['widgets']
    if not widgets:
        return None, ['未发现签章表单域 —— 可能是扫描件，需走图像检测路径（见 SKILL.md 支路 B）']

    groups = classify_widgets(widgets)
    findings = []
    records = []

    # 每个域解析出图像
    for w in widgets:
        ix = widget_image(doc, w['xref'])
        w['img_xref'] = ix
        if ix:
            p = fitz.Pixmap(doc, ix)
            w['img_w'], w['img_h'], w['img_n'] = p.width, p.height, p.n
        else:
            w['img_w'] = w['img_h'] = w['img_n'] = None

    evid = os.path.join(outdir, 'evidence')
    os.makedirs(evid, exist_ok=True)

    log.head('二、印章明细')
    for key, g in sorted(groups.items(), key=lambda kv: str(kv[0])):
        full = sorted(g['full'], key=lambda r: (r['page'], r['y0']))
        seam = sorted(g['seam'], key=lambda r: r['page'])
        label = f'签名者 {key}'
        log(f'\n  【{label}】完整章 {len(full)} 枚 | 骑缝切片 {len(seam)} 片')

        for r in full:
            log(f'    完整章  第{r["page"]:>3}页  {r["name"]:<34} '
                f'{r["w"]}x{r["h"]}pt  图像 {r["img_w"]}x{r["img_h"]}px  '
                f'位置(左{r["x0"]:.0f}, 上{r["y0"]:.0f})')

        if seam:
            pages = [r['page'] for r in seam]
            xs = sorted(set(round(r['x0'], 1) for r in seam))
            ys = sorted(set(round(r['y0'], 1) for r in seam))
            rw = sorted(set(round(r['w'], 2) for r in seam))
            log(f'    骑缝覆盖页: {pages[0]}–{pages[-1]}（共 {len(seam)} 页）')
            log(f'    贴边位置  : x0 = {xs}   (页宽 {seam[0]["page_w"]})')
            log(f'    纵向位置  : y0 = {ys}')
            log(f'    每片尺寸  : {rw} pt 宽')

            # 连续性判据
            missing = [p for p in range(pages[0], pages[-1] + 1) if p not in pages]
            if missing:
                findings.append(f'{label}：骑缝章缺页 {missing}')
                log(f'    ✗ 缺失页  : {missing}')
            else:
                log(f'    ✓ 无缺页  : 从第 {pages[0]} 页到第 {pages[-1]} 页连续覆盖')
            if len(xs) == 1:
                log(f'    ✓ 贴边一致: 所有切片距页边完全相同')
            else:
                findings.append(f'{label}：骑缝切片贴边位置不一致 {xs}')
                log(f'    ✗ 贴边不一致')
            if len(ys) == 1:
                log(f'    ✓ 纵向一致: 叠页时严丝合缝')
            else:
                findings.append(f'{label}：骑缝切片纵向位置不一致 {ys}')
                log(f'    ✗ 纵向不一致 —— 叠页时会错位')

            # 分区精确性：Σ切片宽 vs 完整章宽（宽度无关的强判据）
            if full:
                fw = full[0]['w']
                total = sum(r['w'] for r in seam)
                if abs(total - fw) < 0.05:
                    log(f'    ✓ 精确等分: Σ切片宽 {total:.1f}pt = 完整章宽 {fw:.1f}pt')
                else:
                    log(f'    · 非等分  : Σ切片宽 {total:.1f}pt ≠ 完整章宽 {fw:.1f}pt'
                        f'（若为扫描件属正常，改用残差判定）')
                    findings.append(f'{label}：切片宽度之和与完整章宽度不符（{total:.1f} vs {fw:.1f}pt）')

            # 无缝还原（基于声明几何，不猜宽度）
            strips = []
            for r in seam:
                clip = fitz.Rect(r['x0'], r['y0'], r['x1'], r['y1'])
                pix = doc[r['page'] - 1].get_pixmap(dpi=400, clip=clip)
                strips.append(Image.frombytes('RGB', (pix.width, pix.height), pix.samples))
            if strips:
                W = sum(im.width for im in strips)
                H = max(im.height for im in strips)
                cv = Image.new('RGB', (W, H), (255, 255, 255))
                x = 0
                for im in strips:
                    cv.paste(im, (x, 0))
                    x += im.width
                fn = os.path.join(evid, f'骑缝章还原_{key}.png')
                cv.save(fn)
                log(f'    无缝还原图: {os.path.basename(fn)}  {cv.size}')

            # 每片墨迹占比 —— 检出空白片（可能是被抽换或被遮挡）
            import numpy as np
            covs = []
            for r in seam:
                clip = fitz.Rect(r['x0'], r['y0'], r['x1'], r['y1'])
                pix = doc[r['page'] - 1].get_pixmap(dpi=200, clip=clip)
                im = Image.frombytes('RGB', (pix.width, pix.height), pix.samples)
                a = np.asarray(im).astype(np.int16)
                covs.append(float((a.min(axis=2) < 240).mean()))
            blanks = [seam[i]['page'] for i, c in enumerate(covs) if c < 0.02]
            log(f'    墨迹占比  : {[round(c, 3) for c in covs]}')
            if blanks:
                findings.append(f'{label}：以下页的骑缝切片几乎无墨迹 {blanks}')
                log(f'    ✗ 疑似空白: {blanks}')
            else:
                log(f'    ✓ 每片都有墨迹，无空白页')

        for r in full:
            if r['img_xref']:
                im = pixmap_to_rgb(doc, r['img_xref'])
                if im:
                    fn = os.path.join(evid, f'完整章_p{r["page"]:02d}_{key}_{r["name"]}.png')
                    im.save(fn)

        records.append({'signer': key, 'full': full, 'seam': seam})

    return records, findings


# ────────────────────────────── 密码学验签 ──────────────────────────────
def fmt_asn1_time(s):
    """ASN.1 时间（UTCTime YYMMDDHHMMSS / GeneralizedTime YYYYMMDDHHMMSS）→ 可读，并换算 +08:00。"""
    s = s.strip().rstrip('Z')
    if len(s) == 12:
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = s[2:]
    elif len(s) >= 14:
        year = int(s[0:4])
        rest = s[4:14]
    else:
        return s
    try:
        from datetime import datetime, timedelta, timezone
        mo, d, hh, mi, ss = (int(rest[0:2]), int(rest[2:4]), int(rest[4:6]),
                             int(rest[6:8]), int(rest[8:10]))
        dt = datetime(year, mo, d, hh, mi, ss, tzinfo=timezone.utc)
        local = dt.astimezone(timezone(timedelta(hours=8)))
        return f'{local:%Y-%m-%d %H:%M:%S} +08:00'
    except Exception:
        return f'{year}-{rest[0:2]}-{rest[2:4]} {rest[4:6]}:{rest[6:8]}:{rest[8:10]} UTC'


def verify_signatures(pdf_path, log, openssl, workdir):
    """用原始字节提取 ByteRange / Contents，交 openssl 验签。"""
    log.head('三、密码学验签')
    if not openssl:
        log('  跳过：未找到 openssl 可执行文件')
        return [], ['未执行密码学验签（缺 openssl）']

    raw = open(pdf_path, 'rb').read()
    log(f'  原始文件: {len(raw):,} 字节')

    pat = re.compile(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]')
    found = list(pat.finditer(raw))
    if not found:
        log('  未找到 /ByteRange —— 该 PDF 没有数字签名')
        return [], ['PDF 无数字签名（不是电子签章，或已被移除）']

    log(f'  找到 {len(found)} 个数字签名')
    results, findings = [], []

    for n, m in enumerate(found, 1):
        s1, l1, s2, l2 = (int(m.group(i)) for i in range(1, 5))
        log(f'\n  ── 签名 #{n} ──')
        log(f'    ByteRange : [{s1}, {l1}, {s2}, {l2}]')
        end = max(s1 + l1, s2 + l2)
        covers_all = (end == len(raw))
        log(f'    覆盖到    : {end:,} / {len(raw):,}  '
            + ('✓ 直到文件末尾 —— 签署后无任何追加' if covers_all
               else '（早于末尾：后一次签名覆盖了前一次，属正常）'))

        gap = raw[s1 + l1:s2]
        hx = re.search(rb'<\s*([0-9a-fA-F\s]+?)\s*>', gap, re.S)
        if not hx:
            log('    ✗ 未能从间隙中提取 /Contents')
            findings.append(f'签名 #{n}：无法提取签名值')
            continue
        blob = binascii.unhexlify(re.sub(rb'\s', b'', hx.group(1)))

        content = raw[s1:s1 + l1] + raw[s2:s2 + l2]
        cpath = os.path.join(workdir, f'sig{n}_content.bin')
        spath = os.path.join(workdir, f'sig{n}.der')
        opath = os.path.join(workdir, f'sig{n}_out.bin')
        with open(cpath, 'wb') as f:
            f.write(content)
        with open(spath, 'wb') as f:
            f.write(blob)

        # 注意：签名常为 BER 不定长（30 80 开头），必须喂完整数据，
        # 让 openssl 自己读完最外层对象；按 DER 长度截取或 rstrip(0x00)
        # 都会破坏 EOC 结束标记。
        r = subprocess.run(
            [openssl, 'cms', '-verify', '-inform', 'DER', '-in', spath,
             '-content', cpath, '-binary', '-noverify', '-out', opath],
            capture_output=True, text=True, encoding='utf-8', errors='replace')
        ok = (r.returncode == 0)
        log(f'    验签结果  : ' + ('✓ 通过 —— 被签名数据与签名值一致，未被篡改'
                                   if ok else '✗ 未通过'))
        if not ok and r.stderr:
            log(f'      openssl: {r.stderr.strip().splitlines()[0][:140]}')

        subject = issuer = None
        rc = subprocess.run([openssl, 'pkcs7', '-inform', 'DER', '-in', spath,
                             '-print_certs', '-noout'],
                            capture_output=True, text=True, encoding='utf-8', errors='replace')
        for line in (rc.stdout or '').splitlines():
            t = line.strip()
            if t.startswith('subject='):
                subject = t[len('subject='):].strip()
                log(f'    签名主体  : {subject}')
            elif t.startswith('issuer='):
                issuer = t[len('issuer='):].strip()
                log(f'    签发 CA   : {issuer}')

        rt = subprocess.run([openssl, 'cms', '-inform', 'DER', '-in', spath,
                             '-cmsout', '-print'],
                            capture_output=True, text=True, encoding='utf-8', errors='replace')
        ra = subprocess.run([openssl, 'asn1parse', '-inform', 'DER', '-in', spath],
                            capture_output=True, text=True, encoding='utf-8', errors='replace')

        # 签名时间有两个来源，都要给出来：
        #   /M      —— PDF 签名字典里的签署日期，最直接
        #   TSA     —— CMS 内嵌的 RFC3161 可信时间戳（asn1parse 里最后一个 signingTime）
        # 注意 CMS 里可能有多个 signingTime（证书/TSA 相关），第一个往往不是真正的
        # 签署时间，必须取最后一个。
        window = raw[max(0, m.start() - 800): m.end() + 800]
        mm = re.search(rb'/M\s*\(([^)]*)\)', window)
        pdf_time = None
        if mm:
            pdf_time = mm.group(1).decode('latin-1').strip()
            dm = re.search(r'D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})', pdf_time)
            if dm:
                y, mo, d, hh, mi, ss = dm.groups()
                pdf_time = f'{y}-{mo}-{d} {hh}:{mi}:{ss}'
                off = re.search(r'([+-])(\d{2})\'(\d{2})\'', mm.group(1).decode('latin-1'))
                if off:
                    pdf_time += f' {off.group(1)}{off.group(2)}:{off.group(3)}'

        tsa_time = None
        alines = (ra.stdout or '').splitlines()
        for i, line in enumerate(alines):
            if ':signingTime' in line or 'OBJECT            :signingTime' in line:
                for nxt in alines[i + 1:i + 4]:
                    t = re.search(r'(?:UTCTIME|GENERALIZEDTIME)\s*:(\d{12,14})Z', nxt)
                    if t:
                        tsa_time = fmt_asn1_time(t.group(1))
                        break
        if pdf_time:
            log(f'    签署时间  : {pdf_time}   (PDF 签名字典 /M)')
        if tsa_time:
            log(f'    可信时间戳: {tsa_time}   (CMS 内嵌 RFC3161 时间戳)')
        if not pdf_time and not tsa_time:
            log('    签署时间  : (未能解析)')
        sigtime = pdf_time or tsa_time

        results.append({
            'index': n, 'ok': ok, 'covers_whole_file': covers_all,
            'subject': subject, 'issuer': issuer, 'signing_time': sigtime,
            'byte_range': [s1, l1, s2, l2],
        })
        if not ok:
            findings.append(f'签名 #{n} 验签未通过')
        if not covers_all and n == len(found):
            findings.append('最后一次签名未覆盖到文件末尾 —— 签署后可能有追加内容')

    log('')
    log('  说明: -noverify 表示跳过证书链的「信任」校验（需 Adobe/e签宝 根证书）。')
    log('        它仍然完整校验摘要与签名值是否匹配 —— 通过即证明内容未改。')
    log('        证书是否受信任，请在 Adobe Acrobat 中另行确认（应显示绿色勾）。')
    return results, findings


# ────────────────────────────── 盖章处对账 ──────────────────────────────
def reconcile(doc, seal_records, log):
    log.head('四、盖章处对账')
    all_text = ''.join(p.get_text() for p in doc)
    n_req = all_text.count('（盖章）') + all_text.count('(盖章)')
    n_full = sum(len(r['full']) for r in (seal_records or []))
    log(f'  正文「（盖章）」要求 : {n_req} 处')
    log(f'  实际完整印章         : {n_full} 枚')
    findings = []
    if n_req == 0:
        log('  · 正文未出现「（盖章）」字样 —— 无法自动对账，请人工核对签署栏')
    elif n_req == n_full:
        log('  ✓ 数量一致')
    else:
        msg = f'盖章要求 {n_req} 处，实际印章 {n_full} 枚，数量不符'
        findings.append(msg)
        log(f'  ✗ {msg}')

    # 逐处列出要求位置，便于人工复核
    log('\n  正文要求位置:')
    for i, page in enumerate(doc):
        for line in page.get_text().splitlines():
            if '（盖章）' in line or '(盖章)' in line:
                log(f'    第{i+1:>3}页  {line.strip()[:70]}')
    return n_req, n_full, findings


# ────────────────────────────── 主流程 ──────────────────────────────
def main():
    import fitz

    ap = argparse.ArgumentParser(
        description='合同用印核查：完整章 + 骑缝章 + 密码学验签',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('pdf', help='待核查的 PDF 文件')
    ap.add_argument('-o', '--out', default=None, help='输出目录（默认 <PDF名>_sealcheck）')
    ap.add_argument('--dpi', type=int, default=400, help='骑缝还原渲染 DPI（默认 400）')
    ap.add_argument('--openssl', default=None, help='openssl 可执行文件路径')
    ap.add_argument('--json', action='store_true', help='额外输出 summary.json')
    ap.add_argument('--quiet', action='store_true', help='只写文件，不打印')
    args = ap.parse_args()

    if not os.path.isfile(args.pdf):
        print(f'找不到文件: {args.pdf}')
        return 2

    outdir = args.out or (os.path.splitext(os.path.basename(args.pdf))[0] + '_sealcheck')
    os.makedirs(outdir, exist_ok=True)
    log = Log(quiet=args.quiet)

    log(f'合同用印核查工具 v{VERSION}')
    log(f'文件: {os.path.abspath(args.pdf)}')
    log(f'输出: {os.path.abspath(outdir)}')
    log('')

    ok, openssl = preflight(log)
    if not ok:
        return 3
    log('')

    with open(args.pdf, 'rb') as f:
        data = f.read()
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    log(f'SHA-256: {sha}')
    log(f'大小   : {len(data):,} 字节')

    doc = fitz.open(args.pdf)
    info = probe_structure(doc, log)

    seal_records, find_seal = check_seals(doc, info, log, outdir)

    workdir = tempfile.mkdtemp(prefix='sealcheck_')
    try:
        sig_results, find_sig = verify_signatures(args.pdf, log, openssl, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    n_req, n_full, find_rec = reconcile(doc, seal_records, log)
    doc.close()

    findings = find_seal + find_sig + find_rec

    log.head('五、总结')
    if findings:
        log(f'  发现 {len(findings)} 个需要关注的问题:')
        for i, f in enumerate(findings, 1):
            log(f'    {i}. {f}')
    else:
        log('  ✓ 未发现异常')
    log('')
    log(f'  证据图目录: {os.path.join(os.path.abspath(outdir), "evidence")}')

    report = os.path.join(outdir, '核查报告.md')
    log.save(report)
    print(f'\n报告已写入: {report}')

    if args.json:
        j = {
            'file': os.path.abspath(args.pdf), 'sha256': sha, 'size': len(data),
            'pages': info['pages'], 'producer': info['producer'],
            'is_electronic': info['is_electronic'],
            'seal_requirements': n_req, 'full_seals': n_full,
            'signatures': sig_results,
            'seals': [{'signer': r['signer'],
                       'full': [{k: w[k] for k in ('page', 'name', 'x0', 'y0', 'w', 'h')}
                                for w in r['full']],
                       'seam_pages': [w['page'] for w in r['seam']]}
                      for r in (seal_records or [])],
            'findings': findings,
        }
        jp = os.path.join(outdir, 'summary.json')
        with open(jp, 'w', encoding='utf-8') as f:
            json.dump(j, f, ensure_ascii=False, indent=2)
        print(f'JSON 已写入: {jp}')

    return 0 if not findings else 1


if __name__ == '__main__':
    sys.exit(main())
