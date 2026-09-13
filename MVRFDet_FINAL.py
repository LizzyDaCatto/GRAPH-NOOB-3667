#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  MVRFDet single-file reconstruction prototype                                ║
║  Bản dựng lại một-file để học paper MVRFDet                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

Paper gốc:
    "MVRFDet: Malicious package detection in PyPI ecosystem using multi-view
    representation fusion"
    
*****************************************************************************************************************************

FLOW NÀY CŨ RỒI NÊN TẠM BỎ    
    
Ý tưởng cực ngắn:
    Một package Python không nên được nhìn từ một góc duy nhất. Paper MVRFDet
    nhìn nó qua 3 view rồi fusion lại:

                         ┌──────────────────────────┐
                         │   Input: PyPI package    │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │ Read package statically  │
                         │ Không execute package    │
                         └────────────┬─────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 │                                         │
                 ▼                                         ▼
        ┌──────────────────┐                     ┌──────────────────┐
        │  Metadata files  │                     │ Source code files│
        └────────┬─────────┘                     └────────┬─────────┘
                 │                                        │
                 ▼                                        ▼
        ┌──────────────────────────┐            ┌──────────────────┐
        │ Extract package metadata │            │ Static analysis  │
        │ PKG-INFO / METADATA      │            │ AST + Scalpel    │
        └────────┬─────────────────┘            └────────┬─────────┘
                 │                                        │
                 ▼                                        ▼
        ┌──────────────────┐                     ┌──────────────────┐
        │ Metadata Encoder │                     │  API Call Graph  │
        └────────┬─────────┘                     └───┬──────┬───────┘
                 │                                   │      │
                 │                 ┌─────────────────┘      └─────────────────┐
                 │                 │                                          │
                 ▼                 ▼                                          ▼
        ┌──────────────────┐  ┌──────────────────┐              ┌──────────────────────┐
        │ Feature 1: V_m   │  │ Global API       │              │ Locate sensitive APIs│
        │ Metadata Feature │  │ structure        │              └──────────┬───────────┘
        └────────┬─────────┘  └────────┬─────────┘                         │
                 │                     │                                   ▼
                 │                     │                       ┌──────────────────────┐
                 │                     │                       │ Map APIs to source   │
                 │                     │                       │ code                 │
                 │                     │                       └──────────┬───────────┘
                 │                     │                                  │
                 │                     ▼                                  ▼
                 │            ┌──────────────────────────┐     ┌──────────────────────┐
                 │            │ Fine-grained Control     │     │ Extract suspicious   │
                 │            │ Flow Graph               │     │ API context snippets │
                 │            └────────────┬─────────────┘     └──────────┬───────────┘
                 │                         │                              │
                 │                         ▼                              ▼
                 │            ┌──────────────────┐             ┌──────────────────┐
                 │            │  Graph Encoder   │             │   Code Encoder   │
                 │            └────────┬─────────┘             └────────┬─────────┘
                 │                     │                                │
                 │                     ▼                                ▼
                 │            ┌──────────────────┐             ┌──────────────────────┐
                 │            │ Feature 2: V_g   │             │ Feature 3: V_c       │
                 │            │ Graph Feature    │             │ Code Semantic Feature│
                 │            └────────┬─────────┘             └──────────┬───────────┘
                 │                     │                                  │
                 └─────────────────────┼──────────────────────────────────┘
                                       ▼
                            ┌──────────────────┐
                            │  Feature Matrix  │
                            │ [V_m, V_g, V_c]  │
                            └────────┬─────────┘
                                     │
                                     ▼
                         ┌──────────────────────────┐
                         │ Channel Attention Fusion │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │    Classifier    │
                            └────────┬─────────┘
                                     │
                                     ▼
                         ┌──────────────────────────┐
                         │ Output: Malicious/Benign │
                         └──────────────────────────┘

*****************************************************************************************************************************

FLOW MỚI (VÀO NOTION XEM)                         

flowchart TD
    A["Input package path"] --> B["analyze_package"]
    B --> B1["extract archive if needed"]
    B1 --> B2["iterate package files"]

    B2 --> M1["read_pkg_info"]
    M1 --> RM["Raw metadata: view.metadata"]

    B2 --> S1["safe_read_text for each .py file"]
    S1 --> S2["ast.parse"]
    S2 --> SU["SourceUnit"]
    SU --> PV["PackageVisitor"]

    PV --> C1["visit import nodes"]
    C1 --> RC1["Raw code: view.imports"]

    PV --> C2["visit call nodes and call_name"]
    C2 --> RC2["Raw code: view.api_calls"]

    C2 --> C3["is_sensitive_call"]
    C3 --> C4["_add_snippet"]
    C4 --> RC3["Raw code: view.suspicious_snippets"]

    PV --> C5["visit string constants"]
    C5 --> RC4["Raw code: view.string_literals"]

    PV --> G1["_enter_function and visit_Call"]
    G1 --> RG1["Raw graph: view.call_edges"]

    PV --> G2["visit control-flow nodes"]
    G2 --> G3["_cfg_block"]
    G3 --> RG2["Raw graph: cfg nodes, edges, nesting"]

    B --> SC1["apply_scalpel_cfg"]
    SC1 --> RG2

    B --> SC2["apply_scalpel_call_graph"]
    SC2 --> RG1

    RM --> VIEW["StaticPackageView"]
    RC1 --> VIEW
    RC2 --> VIEW
    RC3 --> VIEW
    RC4 --> VIEW
    RG1 --> VIEW
    RG2 --> VIEW

    VIEW --> STOP1["STOP: enough for raw features"]

    VIEW --> FM["build_paper_like_matrix"]
    FM --> VM["V_m metadata vector"]
    FM --> VC["V_c code vector"]
    FM --> VG["V_g graph vector"]

    VM --> MAT["Feature Matrix"]
    VC --> MAT
    VG --> MAT

    MAT --> ATT["Channel attention"]
    ATT --> PROB["Classifier probability"]
    PROB --> OUT["Malicious or Benign"]

                         
*****************************************************************************************************************************
                         
File này có 3 chế độ chính: [PHẦN NÀY EM SẼ CẬP NHẬT SAU]
    1. predict
       Baseline nhanh. Dùng feature thủ công + heuristic hoặc logistic model.

    2. paper-predict
       Gần paper hơn. Tạo ma trận 3 x 768 gồm metadata/code/graph, sau đó fuse
       bằng channel attention. Nếu thêm --real-encoders thì dùng model thật:
           - all-mpnet-base-v2 cho metadata
           - microsoft/longcoder-base cho code

    3. train-neural
       Prototype train bằng PyTorch CNN + channel attention trên ma trận 3 x 768.
       Đây là nhánh giúp em thấy phần CNN hoạt động như thế nào.

Ví dụ:
    python mvrfdet_single_file.py demo
    python mvrfdet_single_file.py predict D:\Downloads\some_pkg --json
    python mvrfdet_single_file.py paper-predict D:\Downloads\some_pkg --real-encoders --json
    python mvrfdet_single_file.py train-neural --benign D:\good1 D:\good2 --malicious D:\bad1 D:\bad2 --model D:\Downloads\mvrfdet_tiny.pt
"""


from __future__ import annotations

"""
[KO QUAN TRỌNG]
"""

# ==============================================================================
# BẢN ĐỒ LIÊN HỆ VỚI HÌNH TRONG PAPER
# ------------------------------------------------------------------------------
# PAPER PAGE MAP / BẢN ĐỒ TRANG ĐỂ EM ĐỐI CHIẾU NHANH
# ------------------------------------------------------------------------------
# - Section 3.2 "Overview of MVRFDet method"       : PDF page 4, Fig. 3.
# - Section 3.3 "Metadata feature extraction"      : PDF page 4, Fig. 2.
# - Section 3.4 "Code + graph feature extraction"  : PDF pages 4-7, Fig. 3/5/6.
# - Section 3.4.1 "Sensitive APIs list"            : PDF pages 5-6, Fig. 4.
# - Section 3.4.2 "Suspicious APIs snippets"       : PDF page 6, Fig. 5.
# - Section 3.4.3 "Code encoder / LongCoder"       : PDF page 6, Fig. 5.
# - Section 3.4.4 "Graph encoder / GAT"            : PDF pages 6-7, Fig. 6.
# - Section 3.5 "Feature matrix + CAM classifier"  : PDF page 7, Fig. 7, Eq. 15-19.
# - Section 4.1.1 "Implementation details"         : PDF page 8.
# - Section 4.1.2 "Datasets"                       : PDF pages 8-9, Table 1.
# - Section 4.2-4.5 "Evaluation"                   : PDF pages 9-12, Table 2-6, Fig. 8.
#
# Cách đọc source này:
# - Comment ở đầu file là bản đồ tổng quan theo Fig/Section.
# - Comment "PAPER CROSS-REFERENCE" ngay dưới từng STAGE là chỗ đối chiếu chi tiết.
# - Comment trước từng hàm/class nói hàm đó phục vụ khối nào trong Fig. 1/2/3.
# - Nếu comment ghi "Khác paper" nghĩa là source đang mô phỏng/prototype, không
#   phải implementation chính thức của tác giả.
# ------------------------------------------------------------------------------
# FIG. 1 - Ví dụ package độc seccache-0.0.3 import cache_manager.py
#   Paper minh họa một package có __init__.py import file chứa hành vi đáng ngờ.
#   Trong code này, các phần tương ứng là:
#     - SENSITIVE_APIS: chứa socket, subprocess, base64, requests, pickle...
#     - call_name() + is_sensitive_call(): nhận diện API call nhạy cảm từ AST.
#     - PackageVisitor.visit_Call(): bắt API call và lưu snippet quanh vùng nghi ngờ.
#     - analyze_package(): duyệt toàn bộ file .py trong package, gồm __init__.py
#       và cache_manager.py nếu package có cấu trúc giống Fig. 1.
#     - write_demo_package(): tạo demo an toàn mô phỏng kiểu __init__.py gọi
#       cache_manager.py để em test detector mà không chạy mã độc thật.
#
# FIG. 2 - So sánh metadata giữa package độc và package lành tính tương tự
#   Paper cho thấy metadata của package độc có thể bắt chước package thật.
#   Trong code này, các phần tương ứng là:
#     - read_pkg_info(): đọc PKG-INFO / METADATA / setup.cfg / pyproject.toml.
#     - build_feature_dict(): tạo meta_missing_ratio, meta_suspicious_words.
#     - _encode_metadata_real(): encode metadata bằng all-mpnet-base-v2.
#     - build_paper_like_matrix(): đặt metadata vector vào hàng 0, tức V_m.
#
# FIG. 3 - Sơ đồ tổng thể MVRFDet: Metadata + Code + Graph rồi Fusion
#   Đây là hình quan trọng nhất, và phần lớn file này phục vụ Fig. 3.
#   Mapping theo từng khối:
#     - PKG-INFO File Field          -> read_pkg_info()
#     - Metadata Encoder            -> _encode_metadata_real() / _text_dense_hash()
#     - Source Code                 -> safe_read_text(), ast.parse(), SourceUnit
#     - APIs Call Graph             -> PackageVisitor, call_edges, graph_stats()
#     - Suspicious API Snippets     -> PackageVisitor._add_snippet()
#     - Code Encoder                -> _encode_code_real() / _text_dense_hash()
#     - Control Flow Graph          -> cfg_nodes, cfg_edges, max_nesting
#     - Graph Encoder               -> _graph_dense_networkx()
#     - Feature Matrix Generation   -> build_paper_like_matrix() tạo [3, 768]
#     - Channel Attention Fusion    -> _channel_attention(), _paper_like_probability()
#     - CNN Classification          -> _TinyMVRFNetFactory, cmd_train_neural()
#     - Malicious / Benign Output   -> build_report(), cmd_predict(), cmd_paper_predict()
# ==============================================================================



# [IMPORT]

import argparse
import ast
import configparser
import hashlib
import json
import math
import os
import random
import re
import statistics
import sys
import tarfile
import tempfile
import textwrap
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path
from typing import Any, Iterable


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 00 / SETUP                                                           ║
# ║ 0. Cấu hình chung                                                          ║
# ║                                                                            ║
# ║ Các hằng số giới hạn kích thước scan, số file, số snippet.                 ║
# ║ Nếu em muốn detector quét sâu hơn, thường chỉnh ở đây trước.               ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Không có một section riêng trong paper chỉ nói về các hằng số scan như
#   MAX_FILES, MAX_FILE_BYTES, MAX_SNIPPETS, SNIPPET_RADIUS.
# - Liên quan gián tiếp tới Section 4.1.1 "Implementation details", PDF page 8:
#   paper mô tả môi trường chạy, encoder, batch size, epoch, learning rate.
# - Liên quan gián tiếp tới Section 4.4 "Efficiency evaluation", PDF page 11:
#   paper đo thời gian từng bước, nên bản dựng lại cần giới hạn kích thước file
#   để không bị quá tải khi quét package lớn.
# - Khác paper: các giới hạn ở đây là quyết định kỹ thuật của source prototype,
#   không phải hyperparameter chính thức trong paper.



# Các giới hạn này giữ cho quá trình phân tích an toàn và vừa sức máy:
# - Không đọc file quá lớn.
# - Không duyệt vô hạn trong package nhiều thư mục vendored/generated.
# - Không in quá nhiều snippet nghi ngờ làm report bị ngợp.
# --> cấu hình giới hạn scan của file

VERSION = "0.1.0"
HASH_BUCKETS = 128
MAX_FILES = 3000
MAX_FILE_BYTES = 2_000_000
MAX_SNIPPETS = 80
SNIPPET_RADIUS = 18 

"""
VERSION         -> tên phiên bản source
HASH_BUCKETS    -> số ô hash cho fallback vector
MAX_FILES       -> quét tối đa bao nhiêu file
MAX_FILE_BYTES  -> đọc tối đa bao nhiêu byte mỗi file
MAX_SNIPPETS    -> lưu tối đa bao nhiêu snippet
SNIPPET_RADIUS  -> lấy bao nhiêu dòng quanh API đáng nghi
"""




# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 01 / SIGNAL VOCABULARY                                               ║
# ║ 1. Từ điển bề mặt độc hại / Sensitive API list                             ║
# ║                                                                            ║
# ║ Danh sách API/từ khóa làm tín hiệu bề mặt độc hại.                         ║
# ║ Không kết luận một mình; chỉ tăng trọng số khi fuse với view khác.         ║
# ║                                                                            ║
# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.4.1 "Automatic offline extraction of sensitive APIs list",
#   PDF pages 5-6.
# - Paper: Fig. 4, PDF pages 5-6, mô tả role-based prompt engineering để LLM
#   đánh giá candidate sensitive APIs.
# - Paper nói quy trình gốc: Scalpel tạo API call graph cho malicious packages,
#   NetworkX tính 6 centrality metrics, lấy top 500 candidate APIs, sau đó dùng
#   DeepSeek-R1 và GPT-5 để lọc thành 293 sensitive APIs.
# - Source này KHÔNG có full list 293 APIs vì paper không công bố danh sách đó.
# - Vì vậy stage này dùng Bandit blacklist calls/imports làm nguồn có thể kiểm
#   chứng, rồi bổ sung heuristic PyPI-malware để sát bài malicious package hơn.

# Paper MVRFDet nói dùng sensitive API list để định vị vùng code đáng nghi.
# Nhưng trong phần paper mình có, tác giả KHÔNG công bố toàn bộ danh sách API
# chính thức. Vì vậy bản dựng lại này tách nguồn API thành nhiều lớp rõ ràng:
#
#   1) BANDIT_BLACKLIST_CALLS
#      Lấy từ PyCQA Bandit: bandit/blacklists/calls.py
#      Nguồn: https://github.com/PyCQA/bandit/blob/main/bandit/blacklists/calls.py
#      Đây là các lời gọi hàm Python có rủi ro bảo mật phổ biến.
#
#   2) BANDIT_BLACKLIST_IMPORTS
#      Lấy từ PyCQA Bandit: bandit/blacklists/imports.py
#      Nguồn: https://github.com/PyCQA/bandit/blob/main/bandit/blacklists/imports.py
#      Đây là các module/import có rủi ro bảo mật phổ biến.
#
#   3) PYPI_MALWARE_HEURISTIC_APIS + SUSPICIOUS_WORDS
#      Do chị bổ sung để sát bài malicious PyPI package hơn: network, socket,
#      requests, registry Windows, browser cookie, keyring, webhook/token...
#
# Lưu ý quan trọng:
# - Bandit là nguồn tham khảo chính thức cho Python security linting, không phải
#   danh sách official của MVRFDet.
# - Một API/import xuất hiện KHÔNG tự động chứng minh package là malware.
# - Detector chỉ coi chúng là tín hiệu, rồi fuse thêm metadata, code context,
#   API call graph, CFG-lite và semantic embedding để ra xác suất cuối.


"""
ĐOẠN NÀY CHUẨN BỊ DANH SÁCH API CALL, chưa làm gì hết chỉ chuẩn bị
phần bandit này em lấy được từ github, ở trong các phần blacklist và import của nó, em bê nguyên
"""


BANDIT_BLACKLIST_CALLS = {
    # B301 - Deserialization: pickle và các wrapper quanh pickle.
    "pickle.loads", "pickle.load", "pickle.Unpickler",
    "dill.loads", "dill.load", "dill.Unpickler",
    "shelve.open", "shelve.DbfilenameShelf",
    "jsonpickle.decode", "jsonpickle.unpickler.decode",
    "jsonpickle.unpickler.Unpickler", "pandas.read_pickle",

    # B302 - Deserialization: marshal.
    "marshal.load", "marshal.loads",

    # B303 - Hash yếu/insecure hash.
    "Crypto.Hash.MD2.new", "Crypto.Hash.MD4.new", "Crypto.Hash.MD5.new",
    "Crypto.Hash.SHA.new", "Cryptodome.Hash.MD2.new",
    "Cryptodome.Hash.MD4.new", "Cryptodome.Hash.MD5.new",
    "Cryptodome.Hash.SHA.new", "cryptography.hazmat.primitives.hashes.MD5",
    "cryptography.hazmat.primitives.hashes.SHA1",

    # B304/B305 - Cipher hoặc mode yếu.
    "Crypto.Cipher.ARC2.new", "Crypto.Cipher.ARC4.new",
    "Crypto.Cipher.Blowfish.new", "Crypto.Cipher.DES.new",
    "Crypto.Cipher.XOR.new", "Cryptodome.Cipher.ARC2.new",
    "Cryptodome.Cipher.ARC4.new", "Cryptodome.Cipher.Blowfish.new",
    "Cryptodome.Cipher.DES.new", "Cryptodome.Cipher.XOR.new",
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
    "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
    "cryptography.hazmat.primitives.ciphers.algorithms.CAST5",
    "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
    "cryptography.hazmat.primitives.ciphers.algorithms.SEED",
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",
    "cryptography.hazmat.primitives.ciphers.modes.ECB",

    # B306/B307/B308 - Hàm nguy hiểm phổ biến.
    "tempfile.mktemp", "eval", "django.utils.safestring.mark_safe",

    # B310 - URL open/retrieve cần audit scheme.
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "urllib.request.URLopener", "urllib.request.FancyURLopener",
    "six.moves.urllib.request.urlopen", "six.moves.urllib.request.urlretrieve",
    "six.moves.urllib.request.URLopener", "six.moves.urllib.request.FancyURLopener",

    # B311 - Random không phù hợp cho crypto/security token.
    "random.Random", "random.random", "random.randrange", "random.randint",
    "random.choice", "random.choices", "random.uniform", "random.triangular",
    "random.randbytes", "random.sample", "random.getrandbits",

    # B312/B321 - Giao thức clear-text/insecure.
    "telnetlib.Telnet", "ftplib.FTP",

    # B313-B319 - XML parser có rủi ro XML attacks khi parse dữ liệu untrusted.
    "xml.etree.cElementTree.parse", "xml.etree.cElementTree.iterparse",
    "xml.etree.cElementTree.fromstring", "xml.etree.cElementTree.XMLParser",
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.iterparse",
    "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.XMLParser",
    "xml.sax.expatreader.create_parser", "xml.dom.expatbuilder.parse",
    "xml.dom.expatbuilder.parseString", "xml.sax.parse", "xml.sax.parseString",
    "xml.sax.make_parser", "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString", "xml.dom.pulldom.parse",
    "xml.dom.pulldom.parseString",

    # B323 - SSL context không verify cert/hostname.
    "ssl._create_unverified_context",
}

BANDIT_BLACKLIST_IMPORTS = {
    # B401/B402 - Giao thức truyền rõ hoặc kém an toàn.
    "telnetlib", "ftplib",

    # B403/B404 - Deserialize/process execution surface.
    "pickle", "cPickle", "dill", "shelve", "subprocess",

    # B405-B409/B411 - XML parser/XMLRPC risky imports.
    "xml.etree.cElementTree", "xml.etree.ElementTree", "xml.sax",
    "xml.dom.expatbuilder", "xml.dom.minidom", "xml.dom.pulldom", "xmlrpc",

    # B412 - httpoxy-related CGI surfaces.
    "wsgiref.handlers.CGIHandler", "twisted.web.twcgi.CGIScript",
    "twisted.web.twcgi.CGIDirectory",

    # B413/B415 - Deprecated/broken crypto hoặc IPMI insecure module.
    "Crypto.Cipher", "Crypto.Hash", "Crypto.IO", "Crypto.Protocol",
    "Crypto.PublicKey", "Crypto.Random", "Crypto.Signature", "Crypto.Util",
    "pyghmi",
}

PYPI_MALWARE_HEURISTIC_APIS = {
    # Nhóm thực thi động/process: rất hay gặp trong loader/dropper/install hook.
    "exec", "compile", "__import__", "getattr", "setattr",
    "os.system", "os.popen", "os.execv", "os.execve", "os.spawnl",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "pty.spawn", "commands.getoutput",

    # Nhóm outbound/network: Bandit không phủ hết requests/socket vì dùng hợp pháp nhiều.
    "socket.socket", "socket.create_connection", "socket.connect",
    "requests.get", "requests.post", "requests.put", "requests.request",
    "http.client.HTTPConnection", "paramiko.SSHClient",

    # Nhóm file-system touchpoints: tự nó không độc, nhưng đáng chú ý khi đi gần token/exfil.
    "open", "io.open", "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "shutil.copy", "shutil.copyfile", "shutil.move", "os.remove", "os.unlink",
    "os.rename", "os.chmod", "os.chown", "os.walk", "glob.glob",

    # Nhóm encode/decode/dynamic import/archive extraction hay gặp quanh payload.
    "base64.b64decode", "base64.b85decode", "binascii.unhexlify",
    "yaml.load", "importlib.import_module", "importlib.util.module_from_spec",
    "zipfile.ZipFile.extract", "tarfile.TarFile.extractall",

    # Nhóm Windows/credential/browser sensitive surface.
    "ctypes.CDLL", "ctypes.windll", "winreg.OpenKey", "winreg.SetValueEx",
    "keyring.get_password", "browser_cookie3.load",
}

# SENSITIVE_APIS là tập hợp cuối cùng detector dùng khi gặp ast.Call.
SENSITIVE_APIS = BANDIT_BLACKLIST_CALLS | PYPI_MALWARE_HEURISTIC_APIS

# Các từ khóa ngữ nghĩa thường nằm gần logic độc hại. Ví dụ requests.post chỉ là
# API bình thường, nhưng nếu xung quanh có token/cookie/exfiltration/webhook thì
# độ nghi ngờ tăng mạnh hơn.
SUSPICIOUS_WORDS = {
    # -- Từ khóa payload/execution ----------------------------------------
    "payload", "backdoor", "reverse", "shell", "steal", "token", "cookie",
    "credential", "password", "wallet", "clipper", "inject", "dropper",

    # -- Từ khóa exfiltration/persistence/C2 -------------------------------
    "persistence", "exfil", "exfiltration", "webhook", "discord", "telegram",
    "pastebin", "ngrok", "raw.githubusercontent", "powershell", "cmd.exe",
    "/bin/sh", "chmod", "curl", "wget", "base64", "b64decode", "exec", "eval",
}

METADATA_FIELDS = ["name", "summary", "home-page", "author", "author-email", "license", "description"]
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules", "venv", ".venv", "env", ".tox", "dist", "build"}


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 02 / EVIDENCE OBJECTS                                                ║
# ║ 2. Mô hình dữ liệu nội bộ                                                  ║
# ║                                                                            ║
# ║ Các dataclass giữ bằng chứng đã đọc từ package.                            ║
# ║ Mọi stage phía sau đều dùng StaticPackageView làm input chung.             ║
# ║                                                                            ║
# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper không có section riêng nói về dataclass hay cấu trúc dữ liệu nội bộ.
# - Stage này là lớp tổ chức dữ liệu của source để gom các evidence mà Fig. 3
#   cần: metadata view, code view, graph view, snippet, import/API, CFG-lite.
# - Liên quan trực tiếp tới Section 3.2 "Overview of MVRFDet method", PDF page 4,
#   nơi paper chia pipeline thành 5 bước: Metadata Feature Extraction, Code
#   Feature Extraction, Graph Feature Extraction, Feature Matrix Generation,
#   Channel Attention Fusion Classification.
# - Liên quan tới Fig. 3, PDF page 4: StaticPackageView chính là "hồ sơ trung
#   gian" chứa dữ liệu đi qua các khối trong hình.
# - Khác paper: paper mô tả pipeline khái niệm, không công bố schema object/code.

# SourceUnit đại diện cho một file Python sau khi đọc text và parse AST.
# Nếu parse lỗi, lỗi được lưu lại thay vì crash toàn bộ package.
#
# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ CLASS: SOURCEUNIT                                                         ┃
# ┃ CLASS / MỘT FILE PYTHON ĐÃ ĐỌC VÀ PARSE AST                               ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
#
# Định nghĩa class để chứa thông tin của 1 file Python.
@dataclass
class SourceUnit:
    """Một file Python đã được đọc và parse.

    path: đường dẫn tương đối trong package.
    text: nội dung source code.
    tree: AST nếu parse được.
    parse_error: lỗi cú pháp nếu file không parse được.
    """
    path: str
    text: str
    tree: ast.AST | None
    parse_error: str | None = None

"""
Nó biến từng file .py trong package thành một “gói thông tin” có:
path        = file nằm ở đâu
text        = nội dung code dạng chữ
tree        = cây AST nếu parse được
parse_error = lỗi nếu parse thất bại

***********************************************************************************************

[INPUT1: PHARSE THÀNH CÔNG]

INPUT 1 PATH:
cache_manager.py

INPUT 1 TEXT:
import requests

def send(url):
    requests.post(url)

OUTPUT 1:
path: cache_manager.py
text: 'import requests\n\ndef send(url):\n    requests.post(url)\n'
tree type: Module
parse_error: None

***********************************************************************************************

[INPUT 2: PHARSE LỖI]

INPUT 2 PATH:
broken.py

INPUT 2 TEXT:
def send(
    requests.post(url)

OUTPUT 2:
path: broken.py
text: 'def send(\n    requests.post(url)\n'
tree: None
parse_error: SyntaxError: '(' was never closed (<unknown>, line 1)

***********************************************************************************************
-->
analyze_package()
-> đọc từng file .py
-> safe_read_text() lấy text
-> ast.parse(text) tạo tree
-> SourceUnit(path, text, tree, parse_error)
-> đưa unit vào view.sources
"""



# StaticPackageView là bằng chứng của cả package.
# Nó gom mọi thứ mà pipeline cần:
#   - metadata: tên, mô tả, author, license...
#   - sources: danh sách file Python đã parse
#   - api_calls/imports: tín hiệu cho Code View
#   - call_edges/cfg_*: tín hiệu cho Graph View
#   - suspicious_snippets/string_literals/errors: bằng chứng giải thích output


@dataclass
class StaticPackageView:
    """
    Bộ bằng chứng tổng hợp của một package.
    SourceUnit        = 1 file Python
    StaticPackageView = cả package Python

    StaticPackageView gom cả 3 raw feature
    cụ thể là:

1. Metadata raw feature
   -> view.metadata

2. Code raw feature
   -> view.api_calls
   -> view.imports
   -> view.suspicious_snippets
   -> view.string_literals

3. Graph raw feature
   -> view.call_edges
   -> view.cfg_nodes
   -> view.cfg_edges
   -> view.max_nesting


    """
    root: str
    metadata: dict[str, str] = field(default_factory=dict)
    sources: list[SourceUnit] = field(default_factory=list)
    api_calls: Counter[str] = field(default_factory=Counter)
    imports: Counter[str] = field(default_factory=Counter)
    call_edges: Counter[tuple[str, str]] = field(default_factory=Counter)
    cfg_edges: int = 0
    cfg_nodes: int = 0
    max_nesting: int = 0
    suspicious_snippets: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

"""
Nó yêu cầu những thông tin như sau (INPUT):

root = D:/Downloads/demo_pkg

metadata:
name = cache-demo
summary = Demo package

source files:
cache_manager.py
runner.py

api calls:
requests.post
subprocess.Popen

imports:
requests
subprocess

call graph edges:
send -> requests.post
run -> subprocess.Popen

cfg:
nodes = 1
edges = 2
max_nesting = 1

***************************************************************************************************************************************

OUTPUT nó đơn giản là vứt vào các mảng thôi à
root: D:/Downloads/demo_pkg

metadata:
{'name': 'cache-demo', 'summary': 'Demo package'}

sources:
[
  ('cache_manager.py', 'Module', None),
  ('runner.py', 'Module', None)
]

api_calls:
{'requests.post': 1, 'subprocess.Popen': 1}

imports:
{'requests': 1, 'subprocess': 1}

call_edges:
{
  ('cache_manager.py:send', 'requests.post'): 1,
  ('runner.py:run', 'subprocess.Popen'): 1
}

cfg_nodes:
1

cfg_edges:
2

max_nesting:
1

suspicious_snippets:
['# cache_manager.py:4\nrequests.post(url)']

string_literals:
['cmd.exe']

errors:
[]

"""



""""
[HÀM NÀY ĐỂ SAU HÔM 9/9 NGHIÊN CỨU TIẾP]
"""

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: SHA_BUCKET                                                     ┃
# ┃ HÀM / HASH TOKEN THÀNH BUCKET SỐ                                         ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def sha_bucket(text: str, buckets: int = HASH_BUCKETS) -> int:
    """Đưa một chuỗi vào bucket cố định bằng hash.

    Dùng cho fallback embedding/feature hashing. Cùng một token luôn rơi vào
    cùng bucket, nên kết quả ổn định giữa các lần chạy.
    """
    digest = hashlib.blake2b(text.encode("utf-8", "ignore"), digest_size=8).digest()
    return int.from_bytes(digest, "little") % buckets

"""
Ví dụ có HASH_BUCKETS = 128, nghĩa là có 128 ô
sha_bucket() sẽ quyết định mỗi chuỗi nằm ở ô nào
Ví dụ:
sha_bucket("requests.post", 128)      # 57
sha_bucket("subprocess.Popen", 128)   # 12
sha_bucket("pickle.loads", 128)       # 91

Trong paper:
V_m = MPNet, V_c = LongCoder, V_g = GAT.

Trong source mình khi fallback:
V_m/V_c/V_g ≈ hash vector bằng sha_bucket.

haiz dùng tạm vậy
"""


"""
HÀM NÀY PHỤC VỤ CHO GIAI ĐOẠN SAU nên e sẽ giải thích sau
"""

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: SIGMOID                                                         ┃
# ┃ HÀM / ĐỔI SCORE THÀNH XÁC SUẤT 0..1                                       ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def sigmoid(x: float) -> float:
    """Biến điểm thô thành xác suất 0..1.

    Detector cộng nhiều tín hiệu thành score; sigmoid biến score đó thành dạng
    dễ đọc hơn, ví dụ 0.21 benign-ish hoặc 0.99 rất đáng nghi.
    """
    if x < -50:
        return 0.0
    if x > 50:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))

"""
| Score thô `x` | Sau `sigmoid(x)` |
|---:  |---:      |
| `-5` | `0.0067` |
| `-3` | `0.0474` |
| `-2` | `0.1192` |
| `-1` | `0.2689` |
| `0`  | `0.5000` |
| `1`  | `0.7311` |
| `2`  | `0.8808` |
| `3`  | `0.9526` |
| `5`  | `0.9933` |
"""



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: ENTROPY                                                         ┃
# ┃ HÀM / ĐO ĐỘ NGẪU NHIÊN CỦA STRING                                         ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def entropy(text: str) -> float:
    """Tính Shannon entropy của string.

    String entropy cao có thể là base64/token/payload được encode. Đây chỉ là
    tín hiệu phụ, vì nhiều dữ liệu hợp pháp cũng có entropy cao.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())

# Ví dụ entropy:
#   "aaaaaaaaaa"                                 -> 0.0000
#   "hellohello"                                -> 1.9219
#   "requests.post"                             -> 3.2389
#   "c2FmZV90cmFpbmluZ19tYXJrZXJfb25seQ=="       -> khoảng 4.3+
#
# Cách tính:
#   1. Đếm mỗi ký tự xuất hiện bao nhiêu lần.
#   2. Tính xác suất của mỗi ký tự: p = số_lần_xuất_hiện / tổng_số_ký_tự.
#   3. Cộng theo công thức Shannon entropy:
#        entropy = - Σ p * log2(p)
#
#   - Base64/token/payload encoded thường có nhiều ký tự khác nhau,
#     phân bố tương đối đều, nên entropy thường cao.
#


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 03 / SAFE LOADER                                                     ║
# ║ 3. Nạp package an toàn                                                     ║
# ║                                                                            ║
# ║                                                                            ║
# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.4 "Code feature extraction and graph feature extraction",
#   PDF page 4, nói dùng static analysis tool Scalpel để trích API call graph.
# - Paper: Section 4.1.1 "Implementation details", PDF page 8, nhắc Scalpel là
#   công cụ tạo API call graph và control flow graph.
# - Stage này là phần chuẩn bị an toàn trước static analysis: đọc package,
#   giải nén archive nếu cần, parse source code bằng AST.
# - Khác paper: paper không mô tả chi tiết loader cho .whl/.zip/.tar, còn source
#   cần phần này để chạy được trên file/package thật trong Downloads.
# - Ranh giới an toàn: source không import package, không chạy setup.py, không
#   execute target. Đây là quyết định an toàn của bản dựng lại.

# Toàn bộ quá trình là static analysis:
#   - Đọc file bằng text/bytes.
#   - Nếu là .whl/.zip/.tar thì giải nén ra thư mục tạm.
#   - Parse Python bằng ast.
#   - Không import package mục tiêu, không chạy setup.py, không gọi hàm của nó.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: SAFE_READ_TEXT                                                  ┃
# ┃ HÀM / ĐỌC FILE AN TOÀN CÓ GIỚI HẠN SIZE                                   ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def safe_read_text(path: Path) -> str | None:
    """Đọc file an toàn với giới hạn dung lượng.

    Trả None nếu file quá lớn hoặc không đọc được. Thiết kế này giúp một file
    lỗi không làm hỏng toàn bộ quá trình phân tích package.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: EXTRACT_ARCHIVE_IF_NEEDED                                       ┃
# ┃ HÀM / CHUẨN HÓA INPUT FOLDER PY WHL ZIP TAR                               ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def extract_archive_if_needed(path: Path) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """Chuẩn hóa input thành thư mục có thể phân tích.

    - Nếu input là folder: dùng trực tiếp.
    - Nếu input là .whl/.zip/.tar: giải nén vào thư mục tạm.
    - Nếu input là .py: copy vào thư mục tạm như một package một-file.

    Hàm này chỉ giải nén/đọc file, không thực thi nội dung package.
    """
    if not path.exists():
        raise FileNotFoundError(f"Input path does not exist: {path}\nReplace D:\\path\\to\\package_or_file.py with a real .py file, package folder, .whl, .zip, .tar, or .tar.gz path.")
    if path.is_dir():
        return path, None
    tmp = tempfile.TemporaryDirectory(prefix="mvrfdet_pkg_")
    out = Path(tmp.name)
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                zf.extractall(out)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                tf.extractall(out)
        else:
            if path.suffix == ".py":
                copied = out / path.name
                copied.write_bytes(path.read_bytes())
            else:
                raise ValueError(f"Unsupported input: {path}")
    except Exception:
        tmp.cleanup()
        raise
    return out, tmp



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: ITER_PACKAGE_FILES                                              ┃
# ┃ HÀM / DUYỆT FILE TRONG PACKAGE                                            ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def iter_package_files(root: Path, suffixes: tuple[str, ...]) -> Iterable[Path]:
    """Duyệt file trong package theo suffix.

    Bỏ qua các thư mục cache/build/venv để giảm nhiễu và tránh scan quá rộng.
    MAX_FILES chặn package quá lớn hoặc vendored quá nhiều code.
    """
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".eggs")]
        for filename in filenames:
            if filename.endswith(suffixes):
                count += 1
                if count > MAX_FILES:
                    return
                yield Path(dirpath) / filename


# ──────────────────────────────────────────────────────────────────────────
# │ VIEW V_m :: 3.1 Metadata View                                          │
# │ Đọc metadata package và biến nó thành tín hiệu supply-chain.           │

# ──────────────────────────────────────────────────────────────────────────

# Đọc PKG-INFO/METADATA của package PyPI. Các trường thiếu, UNKNOWN hoặc mô tả
# sơ sài là tín hiệu nhẹ, vì nhiều package độc đặt metadata rất nghèo nàn hoặc
# copy từ package thật.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: READ_PKG_INFO                                                   ┃
# ┃ HÀM / ĐỌC METADATA VIEW                                                   ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

# ĐƠN GIẢN HÀM NÀY DÙNG ĐỂ LẤY METADATA 

# FIG. 2 + FIG. 3: hàm này phục vụ Metadata View.
# - FIG. 2: đọc metadata để so sánh package độc/lành tính có thông tin giống nhau không.
# - FIG. 3: tương ứng khối PKG-INFO File Field trước khi vào Metadata Encoder.
#
# Input:
#   root = thư mục gốc của package sau khi đã extract nếu là .whl/.zip/.tar.gz.
#
# Output:
#   dict[str, str] gồm các trường metadata quan trọng, ví dụ:
#   {
#       "name": "requests",
#       "summary": "Python HTTP for Humans.",
#       "author": "Kenneth Reitz",
#       "license": "Apache-2.0",
#       "description": "..."
#   }
#
# Ý nghĩa trong MVRFDet:
#   Đây là bước tạo dữ liệu thô cho Metadata View V_m. Sau đó metadata này được
#   đưa vào _encode_metadata_real() hoặc dense-hash fallback để biến thành vector.

def read_pkg_info(root: Path) -> dict[str, str]:
    """Trích Metadata View từ PKG-INFO/METADATA/setup.cfg/pyproject/setup.py.

    Đây là view V_m: tên package, summary, author, email, license, description.
    Metadata yếu/thiếu không đủ kết luận độc hại, nhưng là một tín hiệu supply
    chain quan trọng khi kết hợp với code view và graph view.
    """

    # result là nơi gom metadata cuối cùng của package.
    # Quy tắc: nguồn nào cho field trước thì giữ trước bằng setdefault/kiểm tra
    # "field_name not in result". Làm vậy để metadata chuẩn trong PKG-INFO hoặc
    # METADATA không bị nguồn phụ phía sau ghi đè linh tinh.
    result: dict[str, str] = {}

    # 1) Ưu tiên đọc PKG-INFO/METADATA.
    # Đây là metadata chuẩn nhất của Python package/wheel/sdist. Trong wheel thường
    # nằm ở *.dist-info/METADATA; trong source distribution có thể là PKG-INFO.
    metadata_candidates = list(iter_package_files(root, ("PKG-INFO", "METADATA")))
    for path in metadata_candidates[:5]:
        text = safe_read_text(path)
        if not text:
            continue

        # Parser().parsestr đọc format email-header kiểu:
        #   Name: package-name
        #   Summary: short text
        #   Author-email: abc@example.com
        msg = Parser().parsestr(text)
        for field_name in METADATA_FIELDS:
            value = msg.get(field_name) or ""
            if value and field_name not in result:
                # " ".join(value.split()) nén whitespace/newline để value gọn,
                # tránh description dài nhiều dòng làm feature bị nhiễu format.
                result[field_name] = " ".join(value.split())

        # Một số file metadata để phần mô tả dài ở payload/body, không nằm trong
        # header Description. Nếu chưa có description thì lấy body này làm mô tả.
        payload = msg.get_payload()
        if isinstance(payload, str) and payload.strip() and "description" not in result:
            result["description"] = " ".join(payload.split())

        # Chỉ cần candidate đầu tiên có dữ liệu là đủ; các candidate còn lại
        # thường là bản trùng trong dist-info/egg-info.
        if result:
            break

    # 2) Đọc setup.cfg nếu package chưa có đủ metadata.
    # File này hay có section [metadata] trong project Python đời cũ/trung gian.
    setup_cfg = root / "setup.cfg"
    if setup_cfg.exists():
        parser = configparser.ConfigParser()
        try:
            parser.read(setup_cfg, encoding="utf-8")
            if parser.has_section("metadata"):
                for key, value in parser.items("metadata"):
                    # setup.cfg có thể viết author_email, còn METADATA dùng
                    # author-email, nên chuẩn hóa về dấu gạch ngang + lowercase.
                    normalized = key.replace("_", "-").lower()
                    if normalized in METADATA_FIELDS and normalized not in result:
                        result[normalized] = " ".join(value.split())
        except configparser.Error:
            # Metadata lỗi format không làm detector crash; thiếu metadata cũng là
            # một tín hiệu nhẹ ở stage build_feature_dict().
            pass

    # 3) Đọc pyproject.toml ở mức đơn giản.
    # Bản này không parse TOML đầy đủ để giữ single-file nhẹ, chỉ bắt các dòng
    # dạng: name = "...", description = "...", license = "...".
    pyproject = root / "pyproject.toml"
    text = safe_read_text(pyproject) if pyproject.exists() else None
    if text:
        for key in ("name", "description", "license"):
            match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]", text)
            if match and key not in result:
                result[key] = match.group(1).strip()

    # 4) Đọc setup.py bằng AST, không execute.
    # Rất quan trọng: KHÔNG chạy setup.py vì package độc có thể giấu payload trong
    # install hook. Ta chỉ parse text thành AST rồi tìm lời gọi setup(...).
    setup_py = root / "setup.py"
    text = safe_read_text(setup_py) if setup_py.exists() else None
    if text:
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                # Bắt cả setup(...) và setuptools.setup(...).
                if isinstance(node, ast.Call) and call_name(node.func).endswith("setup"):
                    for kw in node.keywords:
                        key = (kw.arg or "").replace("_", "-").lower()
                        # Chỉ lấy value dạng string literal. Nếu value là biến/hàm
                        # phức tạp thì bỏ qua, vì static-safe mode không evaluate.
                        if key in METADATA_FIELDS and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            result.setdefault(key, " ".join(kw.value.value.split()))
        except SyntaxError:
            # setup.py lỗi cú pháp thì bỏ qua metadata từ file này; stage đọc source
            # phía sau sẽ ghi parse_error ở SourceUnit nếu cần.
            pass

    # Đây là metadata thô. analyze_package() sẽ nhét nó vào StaticPackageView.metadata,
    # rồi build_feature_dict()/build_paper_like_matrix() mới biến nó thành feature/vector.
    return result


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 04 / AST, API, GRAPH                                                 ║
# ║ 4. Code View + Graph View extraction                                       ║
# ║                                                                            ║
# ║ Đi qua AST để lấy API call, import, snippet, call graph và CFG-lite.       ║
# ║ Phần này biến source code thành bằng chứng phân tích tĩnh.                 ║
# ║                                                                            ║
# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.4, PDF page 4: dùng static analysis để lấy API call graph,
#   locate sensitive APIs, map về source để lấy suspicious API code snippets,
#   rồi dựng CFG cho các snippet.
# - Paper: Section 3.4.2 "Suspicious APIs code context snippets", PDF page 6:
#   mỗi suspicious API lấy tối đa 4096 tokens quanh vị trí API, clip theo boundary,
#   deduplicate snippet trùng, rồi aggregate representation.
# - Paper: Fig. 3, PDF page 4: stage này tương ứng các khối APIs Call Graph,
#   Sensitive APIs Localization, Suspicious APIs Code Context Snippets,
#   Control Flow Graph.
# - Paper: Fig. 5, PDF page 6 liên quan code context snippets; Fig. 6, PDF page 6
#   liên quan graph encoder sau khi có API call graph và CFG.
# - Source hiện tại: dùng Python AST làm nền để không crash trên package lạ, sau đó
#   gọi Scalpel best-effort để bổ sung API call graph và CFG thật hơn. Nếu Scalpel
#   lỗi trên môi trường/package cụ thể, fallback AST vẫn giữ detector chạy được.

# Chuyển AST call node thành tên API dạng dotted name.
# Ví dụ:
#   subprocess.Popen(...)   -> "subprocess.Popen"
#   base64.b64decode(...)   -> "base64.b64decode"
# Việc chuẩn hóa này giúp match sensitive API ổn định hơn.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CALL_NAME                                                       ┃
# ┃ HÀM / LẤY TÊN API CALL TỪ AST                                             ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 1 + FIG. 3: hàm này chuẩn hóa API call từ AST thành tên như socket.socket/subprocess.Popen.
# - FIG. 1: giúp nhận ra lệnh độc trong cache_manager.py.
# - FIG. 3: là bước nền cho APIs Call Graph và Suspicious APIs localization.



def call_name(node: ast.AST) -> str:
    """Khôi phục tên API từ AST call expression.

    Mục tiêu là biến cú pháp Python thành tên ổn định để match sensitive API.
    Ví dụ ast của subprocess.Popen(...) sẽ thành chuỗi "subprocess.Popen".
    """

    # CASE 1: Tên trần / bare name.
    # Ví dụ code: eval("1 + 1")
    # AST phần được gọi là ast.Name(id="eval")
    # Output mình cần: "eval"
    if isinstance(node, ast.Name):
        return node.id

    # CASE 2: Tên có dấu chấm / attribute access.
    # Ví dụ code: subprocess.Popen(...)
    # AST sẽ tách thành:
    #   node.attr  = "Popen"
    #   node.value = ast.Name(id="subprocess")
    # Hàm gọi đệ quy call_name(node.value) để lấy "subprocess",
    # rồi ghép lại thành "subprocess.Popen".
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr

    # CASE 3: Call lồng nhau / nested call.
    # Ví dụ code: get_loader()(payload)
    # AST có thể gặp ast.Call nằm ở vị trí function đang được gọi.
    # Ta bỏ lớp "đang gọi" bên ngoài, rồi lấy tên function thật ở node.func.
    if isinstance(node, ast.Call):
        return call_name(node.func)

    # CASE 4: Truy cập bằng [] rồi gọi tiếp / subscript.
    # Ví dụ code: modules["os"].system("whoami")
    # AST có ast.Subscript cho modules["os"]. Ta lấy phần gốc node.value
    # để vẫn giữ được manh mối tên base thay vì trả rỗng quá sớm.
    if isinstance(node, ast.Subscript):
        return call_name(node.value)

    # CASE 5: Những dạng quá động không khôi phục được tên ổn định.
    # Ví dụ: (lambda x: x)(func) hoặc kết quả từ phép toán phức tạp.
    # Trả "" nghĩa là detector không match API ở node này.
    return ""

# hàm này biến lời gọi hàm trong AST thành chuỗi tên API để detector đem đi so với danh sách API nhạy cảm.


# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: IS_SENSITIVE_CALL                                               ┃
# ┃ HÀM / CHECK API CÓ NHẠY CẢM KHÔNG                                         ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 1 + FIG. 3: hàm này quyết định API call vừa thấy có thuộc sensitive API không.
# - FIG. 1: bắt các API như socket, subprocess, base64 trong ví dụ package độc.
# - FIG. 3: phục vụ khối Sensitive APIs Localization.


def is_sensitive_call(name: str) -> bool:
    """Kiểm tra một API call có thuộc nhóm nhạy cảm không.

    Hàm này dùng cả danh sách Bandit và danh sách PyPI-malware heuristic.
    Nó hỗ trợ match chính xác, match đuôi, và vài keyword fallback để bắt alias
    hoặc dotted name dài mà AST tĩnh không resolve được hoàn toàn.
    """
    if name in SENSITIVE_APIS:
        return True
    tail = name.rsplit(".", 1)[-1]
    if tail in SENSITIVE_APIS:
        return True
    lowered = name.lower()
    return any(word in lowered for word in ("exec", "eval", "socket", "urlopen", "b64decode", "popen", "system"))



def is_sensitive_import(name: str) -> bool:
    """Kiểm tra một import có nằm trong blacklist import của Bandit không.

    Import chỉ cho biết package mở một surface nhạy cảm. Vì vậy feature import
    được tính riêng, không trộn thẳng vào API call count.
    """
    if name in BANDIT_BLACKLIST_IMPORTS:
        return True
    lowered = name.lower()
    for item in BANDIT_BLACKLIST_IMPORTS:
        item_lower = item.lower()
        if lowered == item_lower or lowered.startswith(item_lower + "."):
            return True
    return False


# PackageVisitor đi qua AST của từng file Python và thu thập 2 nhóm chính:
#
# [Code View]
#   - import nào xuất hiện
#   - function/API nào được gọi
#   - API nào nằm trong sensitive list
#   - string nào giống URL/token/base64/high-entropy
#   - snippet quanh API đáng nghi để giải thích report
#
# [Graph View]
#   - cạnh caller -> callee cho call graph đơn giản
#   - số node/cạnh CFG kiểu nhẹ qua if/for/while/try/with
#   - độ nesting, giúp nhận ra logic điều kiện phức tạp quanh hành vi nghi ngờ

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ CLASS: PACKAGEVISITOR                                                     ┃
# ┃ CLASS / AST WALKER LẤY CODE VIEW VÀ GRAPH VIEW                            ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

# AST visitor: nó đi qua từng node trong AST của một file Python để gom bằng chứng
"""
gặp ast.Import             -> gọi visit_Import()
gặp ast.ImportFrom         -> gọi visit_ImportFrom()
gặp ast.FunctionDef        -> gọi visit_FunctionDef()
gặp ast.AsyncFunctionDef   -> gọi visit_AsyncFunctionDef()
gặp ast.Call               -> gọi visit_Call() nếu class có định nghĩa

mở lại lý thuyết AST mình từng viết trong notion là thấy 

nói chung tất cả các phần def này đều xử lý những thứ ast nhả ra
nói chung tất cả các phần def này đều xử lý những thứ ast nhả ra
nói chung tất cả các phần def này đều xử lý những thứ ast nhả ra
cái gì quan trọng phải múa 3 lần
"""

# FIG. 1 + FIG. 3: class này là bộ quét AST chính để lấy Code View và Graph View.
# - FIG. 1: đi vào từng file như __init__.py/cache_manager.py để tìm API đáng nghi.
# - FIG. 3: tạo API call graph, snippet nghi ngờ, CFG-lite và code context.


class PackageVisitor(ast.NodeVisitor):
    """AST walker thu thập Code View và Graph View.

    Visitor này không đánh giá/chạy expression, chỉ đọc cấu trúc AST. Vì vậy kể
    cả package chứa lệnh nguy hiểm thì detector vẫn chỉ nhìn như dữ liệu tĩnh.
    """

    def __init__(self, unit: SourceUnit, view: StaticPackageView) -> None:
        # unit = một file Python cụ thể, gồm path/text/tree AST.
        self.unit = unit
        # view = hồ sơ chung của cả package, nơi mọi bằng chứng được cộng dồn.
        self.view = view
        # scope_stack cho biết hiện visitor đang đứng ở đâu.
        # Ban đầu là <module>, tức vùng ngoài cùng của file.
        self.scope_stack: list[str] = ["<module>"]
        # nesting đo độ lồng của if/for/while/try/with.
        self.nesting = 0
        # lines dùng để cắt snippet quanh API đáng nghi theo số dòng AST báo về.
        self.lines = unit.text.splitlines()

    def visit_Import(self, node: ast.Import) -> Any:
        # Xử lý dạng: import os, import subprocess, import xml.dom.minidom.
        for alias in node.names:
            # Lưu import đầy đủ.
            # Ví dụ: import xml.dom.minidom -> "xml.dom.minidom".
            self.view.imports[alias.name] += 1
            # Lưu thêm root module để match blacklist rộng hơn.
            # Ví dụ: "xml.dom.minidom" -> "xml".
            root = alias.name.split(".")[0]
            if root != alias.name:
                self.view.imports[root] += 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        # Xử lý dạng: from subprocess import Popen, from xml.dom import minidom.
        if node.module:
            # Lưu module đứng sau chữ from.
            # Ví dụ: from xml.dom import minidom -> "xml.dom".
            self.view.imports[node.module] += 1
            # Lưu thêm root module.
            # Ví dụ: "xml.dom" -> "xml".
            root = node.module.split(".")[0]
            if root != node.module:
                self.view.imports[root] += 1
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        # Xử lý function thường: def abc(): ...
        # Đẩy tên function vào scope_stack để lát nữa visit_Call biết API call
        # đang nằm trong function nào.
        self._enter_function(node.name, node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        # Xử lý function async: async def abc(): ...
        # Logic giống FunctionDef, chỉ khác loại node AST.
        self._enter_function(node.name, node)

    def _enter_function(self, name: str, node: ast.AST) -> None:
        # parent = scope hiện tại, ví dụ <module> hoặc function cha.
        parent = self.scope_stack[-1]
        # scoped = tên function có kèm file để tránh trùng tên giữa nhiều file.
        # Ví dụ: cache_manager.py:install_hook.
        scoped = f"{self.unit.path}:{name}"
        # Thêm cạnh call graph: scope cha -> function con.
        self.view.call_edges[(parent, scoped)] += 1
        # Đi vào function: từ đây các API call bên trong được gắn với function này.
        self.scope_stack.append(scoped)
        self.generic_visit(node)
        # Đọc xong function thì quay lại scope trước đó.
        self.scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> Any:
        # Xử lý mọi lời gọi hàm/API: eval(...), requests.post(...), print(...).
        name = call_name(node.func)
        if name:
            # Đếm API/function này xuất hiện bao nhiêu lần trong package.
            self.view.api_calls[name] += 1
            # Thêm cạnh call graph: function hiện tại -> API được gọi.
            self.view.call_edges[(self.scope_stack[-1], name)] += 1
            # Nếu API thuộc nhóm nhạy cảm thì cắt snippet quanh dòng đó.
            if is_sensitive_call(name):
                self._add_snippet(node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> Any:
        # Bắt string literal trong code, ví dụ URL, token, base64, webhook.
        if isinstance(node.value, str) and node.value:
            self.view.string_literals.append(node.value)

    def visit_If(self, node: ast.If) -> Any:
        # if có thể rẽ 2 nhánh: true/false.
        self._cfg_block(node, branch_edges=2)

    def visit_For(self, node: ast.For) -> Any:
        # for có thể đi vào loop hoặc thoát loop.
        self._cfg_block(node, branch_edges=2)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        # async for cũng được tính như loop.
        self._cfg_block(node, branch_edges=2)

    def visit_While(self, node: ast.While) -> Any:
        # while có thể tiếp tục lặp hoặc thoát.
        self._cfg_block(node, branch_edges=2)

    def visit_Try(self, node: ast.Try) -> Any:
        # try có nhánh thành công + mỗi except là một nhánh lỗi.
        self._cfg_block(node, branch_edges=max(2, len(node.handlers) + 1))

    def visit_With(self, node: ast.With) -> Any:
        # with là một block điều khiển nhẹ, ví dụ with open(...) as f.
        self._cfg_block(node, branch_edges=1)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        # async with tương tự with, nhưng dùng trong async code.
        self._cfg_block(node, branch_edges=1)

    def _cfg_block(self, node: ast.AST, branch_edges: int) -> None:
        # CFG-lite: mỗi if/for/while/try/with được tính là một node điều khiển.
        self.view.cfg_nodes += 1
        # branch_edges là số nhánh ước lượng của block đó.
        self.view.cfg_edges += branch_edges
        # Tăng nesting khi đi vào block.
        self.nesting += 1
        # Lưu độ lồng sâu nhất của file/package.
        self.view.max_nesting = max(self.view.max_nesting, self.nesting)
        # Đi tiếp vào bên trong block để vẫn bắt API call/string/function con.
        self.generic_visit(node)
        # Ra khỏi block thì giảm nesting.
        self.nesting -= 1

    def _add_snippet(self, node: ast.AST) -> None:
        # Giới hạn số snippet để report không phình quá lớn.
        if len(self.view.suspicious_snippets) >= MAX_SNIPPETS:
            return
        # Lấy dòng chứa API đáng nghi. Nếu AST không có lineno thì fallback dòng 1.
        lineno = max(1, getattr(node, "lineno", 1))
        # Cắt một cửa sổ quanh dòng đáng nghi.
        start = max(1, lineno - SNIPPET_RADIUS)
        end = min(len(self.lines), lineno + SNIPPET_RADIUS)
        snippet = "\n".join(self.lines[start - 1:end])
        # Lưu kèm file:dòng để report chỉ rõ bằng chứng nằm ở đâu.
        self.view.suspicious_snippets.append(f"# {self.unit.path}:{lineno}\n{snippet}")


"""
███████╗ ██████╗ █████╗ ██╗     ██████╗ ███████╗██╗     
██╔════╝██╔════╝██╔══██╗██║     ██╔══██╗██╔════╝██║     
███████╗██║     ███████║██║     ██████╔╝█████╗  ██║     
╚════██║██║     ██╔══██║██║     ██╔═══╝ ██╔══╝  ██║     
███████║╚██████╗██║  ██║███████╗██║     ███████╗███████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚══════╝
"""


#Scalpel là Python Static Analysis Framework: tool/framework để phân tích code Python mà không chạy code đó. 
# Nó có các module như call graph, control-flow graph, import graph, type inference, SSA… 
# Theo docs chính thức, Scalpel dùng cho các bài toán như bug/vulnerability detection, data-flow analysis, taint analysis, refactoring


# Scalpel integration thật nhưng để ở chế độ best-effort:
# - Nếu Scalpel chạy được, nó bổ sung API call graph và CFG thật hơn AST-lite.
# - Nếu Scalpel lỗi trên package cụ thể, pipeline vẫn giữ bằng chứng AST đã có.
# - Đây là cách an toàn vì package mục tiêu vẫn chỉ bị đọc/parse, không execute.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: APPLY_SCALPEL_CALL_GRAPH                                        ┃
# ┃ HÀM / DÙNG SCALPEL-PYCG ĐỂ BỔ SUNG API CALL GRAPH                         ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.4, PDF page 4: dùng Scalpel để extract API call graph.
# - Paper: Section 4.1.1, PDF page 8: implementation details nhắc lại Scalpel
#   tạo API call graph trong graph feature extraction.
# - Source: hàm này gọi Scalpel/PyCG nếu thư viện hoạt động trên package hiện tại.
#   Nếu PyCG lỗi, source giữ fallback AST call graph từ PackageVisitor.
def apply_scalpel_call_graph(root: Path, view: StaticPackageView) -> None:
    """Bổ sung API Call Graph bằng Scalpel/PyCG nếu chạy được.

    Hàm này phục vụ Graph View trong Fig. 3 của paper:

        Source Code
            -> APIs Call Graph
            -> Graph Encoder
            -> Graph Feature V_g

    Input:
        root:
            Thư mục gốc của package đang phân tích.

        view:
            StaticPackageView đã có sẵn danh sách SourceUnit.
            Hàm này sẽ ghi thêm bằng chứng vào view.call_edges.

    Output:
        Hàm không return dữ liệu mới.
        Nó cập nhật trực tiếp vào view:

            view.call_edges
                Thêm các cạnh call graph do Scalpel/PyCG tìm được.

            view.string_literals
                Thêm dấu vết SCALPEL_CALL_GRAPH_EDGES=N để debug/report.

            view.errors
                Ghi lỗi nếu Scalpel/PyCG không chạy được.

    Quan trọng:
        - Hàm này KHÔNG execute/import package mục tiêu.
        - Nó chỉ đưa đường dẫn file .py cho PyCG phân tích tĩnh.
        - Nếu PyCG lỗi, detector không chết.
          Pipeline vẫn dùng call graph fallback lấy từ AST bằng PackageVisitor.
    """

    # entries là danh sách các file .py sẽ đưa cho Scalpel/PyCG phân tích.
    # Kiểu list[str] nghĩa là danh sách này chỉ chứa chuỗi đường dẫn file.
    # Ban đầu để rỗng, lát nữa duyệt view.sources rồi thêm file hợp lệ vào.
    entries: list[str] = []

    # view.sources là danh sách SourceUnit của package.
    # Mỗi SourceUnit tương ứng với một file Python đã được đọc trước đó:
    #   - unit.path: đường dẫn tương đối của file trong package
    #   - unit.text: nội dung code dạng text
    #   - unit.tree: AST nếu parse được
    #   - unit.parse_error: lỗi cú pháp nếu parse thất bại
    for unit in view.sources:
        # Nếu unit.tree là None, nghĩa là file này parse AST lỗi.
        # PyCG cần file Python có cấu trúc hợp lệ để dựng call graph,
        # nên file lỗi cú pháp sẽ bị bỏ qua thay vì làm crash pipeline.
        if unit.tree is None:
            continue

        # Ghép thư mục gốc package với đường dẫn file bên trong package.
        # Ví dụ:
        #   root = D:/Downloads/pkg
        #   unit.path = cache_manager.py
        #   path = D:/Downloads/pkg/cache_manager.py
        path = root / unit.path

        # Chỉ đưa file vào PyCG nếu file thật sự còn tồn tại trên ổ đĩa.
        # Điều này tránh trường hợp view lưu path nhưng file đã bị thiếu/xóa/lệch.
        if path.exists():
            # path.resolve() đổi path thành đường dẫn tuyệt đối.
            # str(...) đổi Path object thành chuỗi, vì subprocess/PyCG nhận argv dạng string.
            entries.append(str(path.resolve()))

    # Nếu không có file Python hợp lệ nào thì không thể dựng call graph.
    # Hàm dừng tại đây, view giữ nguyên call graph fallback lấy từ AST-lite.
    if not entries:
        return

    try:
        # json: nhận kết quả call graph từ process con.
        # subprocess: chạy PyCG trong process riêng.
        # sys: lấy đúng Python interpreter đang chạy file này.
        import json
        import subprocess
        import sys
        import textwrap

        # worker là một chương trình Python nhỏ, được chạy bằng:
        #     python -c worker <root> <file1.py> <file2.py> ...
        #
        # Vì sao phải tách process con?
        # - PyCG trong Scalpel có import hook khá nhạy.
        # - Nếu nó lỗi hoặc làm bẩn sys.modules/sys.path_importer_cache,
        #   process chính vẫn an toàn.
        # - Process chính chỉ nhận stdout JSON hoặc stderr lỗi.
        worker = r'''
import importlib
import importlib.abc
import json
import sys
import traceback

# root là thư mục gốc của package.
# entries là danh sách file .py cần dựng call graph.
root = sys.argv[1]
entries = sys.argv[2:]
try:
    # Một số bản Scalpel đóng gói PyCG dưới namespace "scalpel.pycg",
    # nhưng code PyCG bên trong lại import theo tên "pycg".
    # Vì vậy đoạn này ép "pycg" trỏ về "scalpel.pycg".
    # Nếu không có đoạn này, PyCG có thể lỗi ModuleNotFoundError.
    #
    # Preload importlib.metadata để import hook của PyCG không chen vào stdlib.
    import importlib.metadata  # noqa: F401

    scalpel_pycg_pkg = importlib.import_module("scalpel.pycg")
    sys.modules["pycg"] = scalpel_pycg_pkg

    # Đăng ký thêm các submodule mà PyCG hay import nội bộ.
    # Mỗi version Scalpel có thể hơi khác nhau, nên thiếu submodule nào thì bỏ qua.
    for submodule in ("formats", "machinery", "processing", "utils"):
        try:
            sys.modules[f"pycg.{submodule}"] = importlib.import_module(f"scalpel.pycg.{submodule}")
        except Exception:
            pass

    # PyCG có module quản lý import riêng.
    # Trên Python 3.11, phần này đôi khi xóa cache/import hook hơi mạnh,
    # có thể làm lỗi stdlib hoặc lỗi khi module hiện tại chưa có node.
    imports_mod = importlib.import_module("scalpel.pycg.machinery.imports")
    original_create_edge = imports_mod.ImportManager.create_edge

    def safe_create_edge(self, dest):
        # Nếu PyCG chưa biết module hiện tại là gì thì không tạo cạnh.
        # Mục tiêu là tránh lỗi missing node/None node.
        if not self.get_node(self._get_module_path()):
            return

        # Nếu đủ thông tin thì dùng logic gốc của PyCG.
        return original_create_edge(self, dest)

    def safe_clear_caches(self):
        # Bản gốc có thể xóa cache quá rộng.
        # Bản vá này chỉ xóa các module do import_graph của PyCG theo dõi.
        for name in list(self.import_graph):
            if name in sys.modules:
                del sys.modules[name]

    # Gắn hai bản vá nhẹ vào PyCG trong process con.
    imports_mod.ImportManager.create_edge = safe_create_edge
    imports_mod.ImportManager._clear_caches = safe_clear_caches
    sys.modules["pycg.machinery.imports"] = imports_mod

    # CallGraphGenerator là class chính của PyCG.
    # Nó phân tích tĩnh các file Python để suy ra hàm nào gọi hàm nào.
    from scalpel.pycg.pycg import CallGraphGenerator

    # Tạo bộ sinh call graph từ danh sách file đầu vào và root package.
    generator = CallGraphGenerator(entries, root)

    # Chạy phân tích tĩnh. Bước này đọc code, AST, import, function, call...
    # nhưng không execute package mục tiêu.
    generator.analyze()

    # In danh sách cạnh call graph ra stdout dạng JSON để process chính đọc.
    # Ví dụ cạnh:
    #     ["pkg.main", "pkg.collect"]
    #     ["pkg.collect", "requests.post"]
    print(json.dumps(generator.output_edges()))
except Exception:
    # Nếu process con lỗi, in traceback ra stderr rồi thoát mã 2.
    # Process chính sẽ bắt returncode != 0 và ghi lỗi vào view.errors.
    traceback.print_exc(file=sys.stderr)
    raise SystemExit(2)
'''

        # Chạy worker trong process Python riêng.
        # capture_output=True để lấy stdout/stderr về xử lý.
        # timeout=45 để tránh kẹt mãi trên package lớn hoặc PyCG lỗi vòng lặp.
        completed = subprocess.run(
            [sys.executable, "-c", worker, str(root.resolve()), *entries],
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )

        # Nếu process con báo lỗi, lấy dòng lỗi cuối cùng cho gọn,
        # rồi ném RuntimeError để khối except ngoài ghi vào view.errors.
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()[-1:]
            raise RuntimeError(detail[0] if detail else f"PyCG exited with {completed.returncode}")

        # Nếu chạy thành công, stdout là JSON chứa các cạnh call graph.
        edges = json.loads(completed.stdout or "[]")
        added = 0

        for src, dst in edges:
            src_name = str(src)
            dst_name = str(dst)

            # Thêm cạnh vào Raw Graph Feature:
            #     view.call_edges[(caller, callee)] += 1
            #
            # Prefix "scalpel:" giúp phân biệt cạnh lấy từ Scalpel/PyCG
            # với cạnh fallback do PackageVisitor tự lấy bằng AST-lite.
            view.call_edges[(f"scalpel:{src_name}", f"scalpel:{dst_name}")] += 1

            # Không tăng api_calls thật ở đây.
            # += 0 chỉ giữ dấu vết tên callee nếu Counter cần hiển thị key,
            # nhưng không làm sai số lượng API call đã lấy từ AST.
            view.api_calls[dst_name.rsplit(".", 1)[-1] if dst_name else dst_name] += 0
            added += 1

        # Ghi dấu vết debug/report: Scalpel đã thêm được bao nhiêu cạnh.
        if added:
            view.string_literals.append(f"SCALPEL_CALL_GRAPH_EDGES={added}")

    except Exception as exc:
        # Nếu bất kỳ bước nào lỗi, detector không crash.
        # Lỗi được lưu vào view.errors; các bước sau vẫn dùng AST fallback.
        view.errors.append(f"Scalpel/PyCG call graph unavailable: {exc.__class__.__name__}: {exc}")

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: APPLY_SCALPEL_CFG                                               ┃
# ┃ HÀM / DÙNG SCALPEL CFGBUILDER ĐỂ BỔ SUNG CONTROL FLOW GRAPH               ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.4, PDF page 4: sau khi locate suspicious APIs, paper dựng
#   control flow graph cho suspicious API code context snippets.
# - Paper: Section 4.1.1, PDF page 8: CFG cũng được extract bằng Scalpel.
# - Source: hàm này dùng Scalpel CFGBuilder để lấy block/exits thật từ từng file.
#   Nó chưa cắt đúng snippet 4096 tokens như paper, nhưng CFG không còn chỉ là
#   counter AST-lite nữa.
def apply_scalpel_cfg(root: Path, view: StaticPackageView) -> None:
    """Bổ sung CFG nodes/edges bằng Scalpel CFGBuilder.

    CFGBuilder trả về các CFG con cho module/function/class. Source cộng số block
    và số exit edge vào view.cfg_nodes/view.cfg_edges để Graph View có tín hiệu
    gần Scalpel hơn. Nếu Scalpel lỗi ở một file, lỗi được ghi lại và file khác
    vẫn tiếp tục.
    """
    try:
        from scalpel.cfg.builder import CFGBuilder
    except Exception as exc:
        view.errors.append(f"Scalpel CFGBuilder unavailable: {exc.__class__.__name__}: {exc}")
        return

    total_blocks = 0
    total_exits = 0
    for unit in view.sources:
        if unit.tree is None:
            continue
        path = root / unit.path
        if not path.exists():
            continue
        try:
            cfgs = CFGBuilder().build_from_file(Path(unit.path).stem, str(path), flattened=True)
            if isinstance(cfgs, dict):
                iterable = cfgs.values()
            else:
                iterable = [cfgs]
            for cfg in iterable:
                blocks = list(cfg)
                total_blocks += len(blocks)
                total_exits += sum(len(getattr(block, "exits", [])) for block in blocks)
        except Exception as exc:
            view.errors.append(f"Scalpel CFG failed for {unit.path}: {exc.__class__.__name__}: {exc}")

    if total_blocks or total_exits:
        # Giữ số AST-lite đã có, rồi cộng thêm bằng chứng CFG thật từ Scalpel.
        view.cfg_nodes += total_blocks
        view.cfg_edges += total_exits
        view.string_literals.append(f"SCALPEL_CFG_BLOCKS={total_blocks};SCALPEL_CFG_EDGES={total_exits}")


# Hàm trung tâm của static pipeline. Input có thể là:
#   - thư mục package
#   - một file .py
#   - wheel .whl
#   - .zip / .tar / .tar.gz
# Output là StaticPackageView, dùng lại cho cả predict, paper-predict và train.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: ANALYZE_PACKAGE                                                 ┃
# ┃ HÀM / CHẠY TOÀN BỘ STATIC ANALYSIS                                        ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 1 + FIG. 2 + FIG. 3: hàm tổng điều phối static analysis cho cả package.
# - FIG. 1: quét toàn bộ source code package.
# - FIG. 2: gọi read_pkg_info() để lấy metadata.
# - FIG. 3: tạo StaticPackageView làm input chung cho 3 view trước khi fusion.
def analyze_package(package_path: str | Path) -> StaticPackageView:
    """Chạy toàn bộ static-analysis stage cho một package.

    Output của hàm là StaticPackageView, tức bản chụp bằng chứng dùng chung cho:
    predict, paper-predict, sensitive-apis, train và train-neural.
    """
    original = Path(package_path).resolve()
    root, tmp = extract_archive_if_needed(original)
    try:
        view = StaticPackageView(root=str(original))
        view.metadata = read_pkg_info(root)
        for py_file in iter_package_files(root, (".py",)):
            text = safe_read_text(py_file)
            if text is None:
                continue
            rel = str(py_file.relative_to(root)).replace("\\", "/")
            try:
                tree = ast.parse(text, filename=rel)
                unit = SourceUnit(rel, text, tree)
                PackageVisitor(unit, view).visit(tree)
            except SyntaxError as exc:
                unit = SourceUnit(rel, text, None, str(exc))
                view.errors.append(f"{rel}: {exc}")
            view.sources.append(unit)
        # Paper dùng Scalpel ở graph feature extraction. Source vẫn giữ AST scan
        # làm nền, rồi gọi Scalpel best-effort để bổ sung CFG/call graph thật hơn.
        apply_scalpel_cfg(root, view)
        apply_scalpel_call_graph(root, view)
        return view
    finally:
        if tmp is not None:
            tmp.cleanup()





"""
----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------
"""


# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: GRAPH_STATS                                                     ┃
# ┃ HÀM / TÍNH THỐNG KÊ CALL GRAPH                                            ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: hàm này phục vụ Graph Feature.
# Nó đo thống kê call graph trước khi graph được đưa vào graph encoder/fusion.
def graph_stats(edges: Counter[tuple[str, str]]) -> dict[str, float]:
    """Tính vài thống kê đơn giản từ call graph.

    Các thống kê này giúp baseline hiểu package có graph gọi hàm dày/phức tạp
    hay không, trước khi graph được encode sâu hơn bằng NetworkX.
    """
    nodes = set()
    indeg = Counter()
    outdeg = Counter()
    for (src, dst), weight in edges.items():
        nodes.add(src)
        nodes.add(dst)
        outdeg[src] += weight
        indeg[dst] += weight
    n = len(nodes)
    m = sum(edges.values())
    if not n:
        return {"graph_nodes": 0, "graph_edges": 0, "graph_density": 0.0, "max_indegree": 0, "max_outdegree": 0, "avg_degree": 0.0}
    density = m / max(1, n * (n - 1))
    return {
        "graph_nodes": float(n),
        "graph_edges": float(m),
        "graph_density": density,
        "max_indegree": float(max(indeg.values() or [0])),
        "max_outdegree": float(max(outdeg.values() or [0])),
        "avg_degree": float((sum(indeg.values()) + sum(outdeg.values())) / n),
    }



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: TEXT_WORD_FEATURES                                              ┃
# ┃ FUNCTION / KHỐI XỬ LÝ TEXT_WORD_FEATURES                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def text_word_features(prefix: str, text: str, features: dict[str, float]) -> None:
    """Đếm từ khóa đáng nghi trong một đoạn text.

    prefix cho biết feature thuộc metadata hay snippet/code context, để report và
    scoring phân biệt được tín hiệu đến từ view nào.
    """
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.lower())
    for word, count in Counter(words).most_common(500):
        features[f"{prefix}_hash_{sha_bucket(word)}"] = features.get(f"{prefix}_hash_{sha_bucket(word)}", 0.0) + min(count, 10) / 10.0


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 05 / NUMERIC FEATURES                                                ║
# ║ 5. Feature engineering                                                     ║
# ║                                                                            ║
# ║ Nén metadata/code/graph evidence thành feature_dict dễ debug.              ║
# ║ Nhánh baseline train/predict dùng các feature này.                         ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.2, PDF page 4, nói ba view chính được đưa vào fusion:
#   metadata, code semantics, graph structure.
# - Paper: Section 3.3, PDF page 4: metadata lấy 7 field từ PKG-INFO và encode
#   bằng all-mpnet-base-v2 thành vector V_m 768 chiều.
# - Paper: Section 3.4, PDF pages 4-7: code snippet và graph được encode bằng
#   LongCoder/GAT để tạo V_c và V_g.
# - Stage này là nhánh baseline dễ đọc: thay vì chỉ dùng embedding neural, nó
#   tạo feature_dict số hóa thủ công để debug từng bằng chứng.
# - Khác paper: feature_dict không phải representation chính thức của MVRFDet;
#   nó giúp source có thể train/predict khi chưa có dataset, GAT, classifier gốc.

# Nén hồ sơ bằng chứng thành vector số cho baseline classifier:
#   - Metadata: thiếu field, từ khóa đáng nghi trong name/summary/description
#   - Code: tổng sensitive APIs, mật độ API, từ khóa quanh snippet
#   - String: URL, entropy cao, payload-looking strings
#   - Graph: số cạnh call graph, degree trung bình, CFG edges/nodes/nesting
# Đây là bản feature thủ công để có thể train/test khi không có dataset gốc.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: BUILD_FEATURE_DICT                                              ┃
# ┃ HÀM / GOM FEATURE THÀNH DICT SỐ                                           ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 2 + FIG. 3: hàm này biến bằng chứng 3 view thành feature số dễ train/dự đoán.
# - FIG. 2: dùng metadata quality/suspicious words.
# - FIG. 3: dùng metadata + code + graph signals trước bước classification.
def build_feature_dict(view: StaticPackageView) -> dict[str, float]:
    """Biến StaticPackageView thành feature_dict số hóa.

    feature_dict là nhánh nhẹ, dễ debug: mỗi key là một tín hiệu rõ nghĩa. Nó
    song song với ma trận 3 x 768 ở paper-like mode.
    """
    f: dict[str, float] = {}
    total_meta = len(METADATA_FIELDS)
    missing = 0
    metadata_text_parts = []
    for field_name in METADATA_FIELDS:
        value = view.metadata.get(field_name, "")
        metadata_text_parts.append(value)
        if not value or value.upper() in {"UNKNOWN", "NONE", "NULL", "N/A"}:
            missing += 1
        f[f"meta_has_{field_name}"] = 1.0 if value else 0.0
        f[f"meta_len_{field_name}"] = min(len(value), 5000) / 5000.0
    metadata_text = " ".join(metadata_text_parts)
    f["meta_missing_ratio"] = missing / total_meta
    f["meta_entropy"] = entropy(metadata_text) / 8.0
    f["meta_suspicious_words"] = sum(1 for w in SUSPICIOUS_WORDS if w in metadata_text.lower()) / 20.0
    text_word_features("meta", metadata_text, f)

    f["source_file_count"] = min(len(view.sources), 1000) / 1000.0
    parse_error_count = sum(1 for unit in view.sources if unit.parse_error)
    f["parse_error_ratio"] = parse_error_count / max(1, len(view.sources))
    f["api_unique_count"] = min(len(view.api_calls), 1000) / 1000.0
    f["api_total_count"] = min(sum(view.api_calls.values()), 10000) / 10000.0
    f["sensitive_api_unique"] = min(sum(1 for api in view.api_calls if is_sensitive_call(api)), 100) / 100.0
    f["sensitive_api_total"] = min(sum(c for api, c in view.api_calls.items() if is_sensitive_call(api)), 500) / 500.0
    f["sensitive_import_unique"] = min(sum(1 for imp in view.imports if is_sensitive_import(imp)), 100) / 100.0
    f["sensitive_import_total"] = min(sum(c for imp, c in view.imports.items() if is_sensitive_import(imp)), 500) / 500.0

    for api, count in view.api_calls.most_common(1000):
        f[f"api_hash_{sha_bucket(api)}"] = f.get(f"api_hash_{sha_bucket(api)}", 0.0) + min(count, 20) / 20.0
        if is_sensitive_call(api):
            f[f"sapi_hash_{sha_bucket(api)}"] = f.get(f"sapi_hash_{sha_bucket(api)}", 0.0) + min(count, 20) / 20.0
    for imp, count in view.imports.most_common(300):
        f[f"import_hash_{sha_bucket(imp)}"] = f.get(f"import_hash_{sha_bucket(imp)}", 0.0) + min(count, 20) / 20.0
        if is_sensitive_import(imp):
            f[f"simport_hash_{sha_bucket(imp)}"] = f.get(f"simport_hash_{sha_bucket(imp)}", 0.0) + min(count, 20) / 20.0

    stats = graph_stats(view.call_edges)
    f.update({k: min(v, 1.0) if k.endswith("density") else min(v, 10000.0) / 10000.0 for k, v in stats.items()})
    f["cfg_nodes"] = min(view.cfg_nodes, 5000) / 5000.0
    f["cfg_edges"] = min(view.cfg_edges, 10000) / 10000.0
    f["max_nesting"] = min(view.max_nesting, 50) / 50.0

    snippets_text = "\n".join(view.suspicious_snippets)
    f["snippet_count"] = min(len(view.suspicious_snippets), MAX_SNIPPETS) / MAX_SNIPPETS
    f["snippet_suspicious_words"] = sum(snippets_text.lower().count(w) for w in SUSPICIOUS_WORDS) / 50.0
    f["snippet_entropy"] = entropy(snippets_text) / 8.0
    text_word_features("code", snippets_text, f)

    suspicious_strings = [s for s in view.string_literals if entropy(s) > 4.2 and len(s) > 30]
    urls = [s for s in view.string_literals if re.search(r"https?://|ftp://|discord|telegram|pastebin|raw\.github", s, re.I)]
    f["high_entropy_string_count"] = min(len(suspicious_strings), 100) / 100.0
    f["url_string_count"] = min(len(urls), 100) / 100.0
    f["long_string_count"] = min(sum(1 for s in view.string_literals if len(s) > 120), 200) / 200.0
    return f



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: VECTORIZE                                                       ┃
# ┃ FUNCTION / KHỐI XỬ LÝ VECTORIZE                                           ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def vectorize(feature_dict: dict[str, float], vocabulary: list[str] | None = None) -> tuple[list[float], list[str]]:
    """Chuyển dict feature thành vector cho logistic model.

    Khi train, vocabulary được tạo từ toàn bộ feature. Khi predict bằng model đã
    lưu, dùng lại vocabulary cũ để thứ tự vector không bị lệch.
    """
    if vocabulary is None:
        vocabulary = sorted(feature_dict)
    return [float(feature_dict.get(k, 0.0)) for k in vocabulary], vocabulary


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 06 / BASELINE MODEL                                                  ║
# ║ 6. Baseline trainable nhẹ: Logistic Fusion                                 ║
# ║                                                                            ║
# ║ Logistic classifier nhỏ để train thử khi chưa có dataset/model gốc.        ║
# ║ Dễ hiểu, dễ lưu JSON, phù hợp demo học pipeline.                           ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper không dùng logistic model này làm classifier chính.
# - Paper: Section 3.5, PDF page 7: classifier chính là CNN + Channel Attention
#   + MLP trên feature matrix ba kênh.
# - Paper: Section 4.1.1, PDF page 8: training dùng cross entropy loss, Adam,
#   learning rate 2e-5, batch size 8, 100 epochs.
# - Stage này là baseline/prototype do source thêm để em có một mô hình nhẹ,
#   dễ train, dễ lưu JSON và dễ giải thích score.
# - Khi đối chiếu paper, coi stage này là công cụ học/debug, không phải module
#   chính thức trong kiến trúc MVRFDet.

# Model nhỏ này giúp em train thử trên folder benign/malicious của riêng mình.
# Nó KHÔNG phải model trong paper, nhưng hữu ích để kiểm tra pipeline học máy
# end-to-end: extract feature -> train -> save model -> predict lại.
@dataclass
class FusionLogisticModel:
    """Logistic classifier nhỏ có thể lưu/load bằng JSON.

    Model này tiện cho bài học và demo, không phải weight gốc của MVRFDet.
    """
    vocabulary: list[str]
    weights: list[float]
    bias: float
    threshold: float = 0.5


# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: PREDICT_PROBA                                                   ┃
# ┃ FUNCTION / KHỐI XỬ LÝ PREDICT_PROBA                                       ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    def predict_proba(self, feature_dict: dict[str, float]) -> float:
        x, _ = vectorize(feature_dict, self.vocabulary)
        score = self.bias + sum(w * xi for w, xi in zip(self.weights, x))
        return sigmoid(score)


# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: TO_JSON                                                         ┃
# ┃ FUNCTION / KHỐI XỬ LÝ TO_JSON                                             ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    def to_json(self) -> dict[str, Any]:
        return {"version": VERSION, "vocabulary": self.vocabulary, "weights": self.weights, "bias": self.bias, "threshold": self.threshold}

    @classmethod

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: FROM_JSON                                                       ┃
# ┃ FUNCTION / KHỐI XỬ LÝ FROM_JSON                                           ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    def from_json(cls, data: dict[str, Any]) -> "FusionLogisticModel":
        return cls(list(data["vocabulary"]), list(map(float, data["weights"])), float(data["bias"]), float(data.get("threshold", 0.5)))



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: TRAIN_MODEL                                                     ┃
# ┃ HÀM / TRAIN LOGISTIC BASELINE                                             ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def train_model(samples: list[tuple[dict[str, float], int]], epochs: int = 80, lr: float = 0.08, seed: int = 7) -> FusionLogisticModel:
    """Train logistic baseline bằng gradient descent nhỏ gọn.

    Đây là model học máy tối giản để em có một đường train end-to-end không phụ
    thuộc GPU hay dataset lớn.
    """
    vocab = sorted({k for feats, _ in samples for k in feats})
    xs = [vectorize(feats, vocab)[0] for feats, _ in samples]
    ys = [label for _, label in samples]
    weights = [0.0] * len(vocab)
    bias = 0.0
    rng = random.Random(seed)
    order = list(range(len(xs)))
    l2 = 0.0005
    for _ in range(epochs):
        rng.shuffle(order)
        for idx in order:
            x = xs[idx]
            y = ys[idx]
            p = sigmoid(bias + sum(w * xi for w, xi in zip(weights, x)))
            err = p - y
            bias -= lr * err
            for i, xi in enumerate(x):
                if xi:
                    weights[i] -= lr * (err * xi + l2 * weights[i])
    return FusionLogisticModel(vocab, weights, bias)


# Scoring thủ công khi chưa có model train. Mỗi nhóm tín hiệu cộng điểm:
# sensitive API, suspicious word, URL, entropy cao, metadata yếu, CFG phức tạp.
# Sau đó sigmoid(score - bias) biến thành xác suất 0..1.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: HEURISTIC_PROBABILITY                                           ┃
# ┃ HÀM / TÍNH SCORE HEURISTIC                                                ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: hàm này là classifier heuristic thay cho classifier gốc khi chưa train model.
# Output của nó tương ứng nhánh cuối Malicious Package / Benign Package.
def heuristic_probability(features: dict[str, float]) -> tuple[float, list[str]]:
    """Tính xác suất bằng luật thủ công khi chưa train model.

    Hàm này cố tình trả kèm reasons để em thấy feature nào đang đẩy score lên.
    Nó hữu ích khi kiểm thử detector bằng package thật hoặc fixture an toàn.
    """
    reasons = []
    score = 0.0

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: ADD                                                             ┃
# ┃ FUNCTION / KHỐI XỬ LÝ ADD                                                 ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    def add(name: str, weight: float, reason: str) -> None:
        nonlocal score
        value = features.get(name, 0.0)
        if value > 0:
            score += weight * value
            reasons.append(reason)

    add("sensitive_api_total", 8.0, "uses sensitive APIs")
    add("sensitive_import_total", 3.5, "imports Bandit-blacklisted security-sensitive modules")
    add("snippet_suspicious_words", 4.0, "suspicious words appear near sensitive API code")
    add("url_string_count", 3.0, "contains URL-like strings")
    add("high_entropy_string_count", 3.0, "contains high-entropy strings")
    add("meta_missing_ratio", 1.8, "metadata fields are missing or weak")
    add("parse_error_ratio", 1.2, "some Python files could not be parsed")
    add("cfg_edges", 1.0, "non-trivial control flow around code")
    probability = sigmoid(score - 2.2)
    return probability, reasons[:8]


# Report luôn giữ bằng chứng đi kèm xác suất, để em không chỉ thấy "malicious"
# mà còn thấy vì sao: import gì, sensitive API nào, snippet nào bị bắt.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: BUILD_REPORT                                                    ┃
# ┃ HÀM / TẠO OUTPUT JSON/HUMAN REPORT                                        ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: hàm này gom kết quả cuối để in ra malicious/benign và bằng chứng đi kèm.
# Nó không nằm trong paper model, nhưng giúp em đọc được vì sao detector kết luận như vậy.
def build_report(path: str, view: StaticPackageView, features: dict[str, float], probability: float, reasons: list[str]) -> dict[str, Any]:
    """Đóng gói output phân tích thành dict có thể in JSON.

    Report giữ cả kết luận lẫn bằng chứng: metadata, số lượng file, API nhạy cảm,
    import nổi bật, lý do, và snippet nghi ngờ.
    """
    sensitive = {api: c for api, c in view.api_calls.most_common() if is_sensitive_call(api)}
    sensitive_imports = {imp: c for imp, c in view.imports.most_common() if is_sensitive_import(imp)}
    parse_error_count = sum(1 for unit in view.sources if unit.parse_error)
    return {
        "input": path,
        "prediction": "malicious" if probability >= 0.5 else "benign",
        "malicious_probability": round(probability, 4),
        "metadata": view.metadata,
        "counts": {
            "python_files": len(view.sources),
            "parse_errors": parse_error_count,
            "analysis_errors": len(view.errors),
            "unique_api_calls": len(view.api_calls),
            "call_graph_edges": sum(view.call_edges.values()),
            "cfg_nodes": view.cfg_nodes,
            "cfg_edges": view.cfg_edges,
            "snippets": len(view.suspicious_snippets),
        },
        "top_imports": view.imports.most_common(15),
        "top_sensitive_imports": list(sensitive_imports.items())[:20],
        "top_sensitive_apis": list(sensitive.items())[:20],
        "reasons": reasons,
        "analysis_errors": view.errors[:10],
        "snippets": view.suspicious_snippets[:5],
    }



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: PRINT_HUMAN_REPORT                                              ┃
# ┃ FUNCTION / KHỐI XỬ LÝ PRINT_HUMAN_REPORT                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def print_human_report(report: dict[str, Any]) -> None:
    """In report dạng dễ đọc cho terminal.

    Dùng khi không bật --json. Nếu em cần copy vào notebook/report, --json thường
    sạch hơn.
    """
    print(f"MVRFDet single-file prototype v{VERSION}")
    print(f"Input: {report['input']}")
    print(f"Prediction: {report['prediction']}  probability={report['malicious_probability']}")
    print("\nCounts:")
    for k, v in report["counts"].items():
        print(f"  {k}: {v}")
    if report.get("top_sensitive_imports"):
        print("\nTop sensitive imports:")
        for imp, count in report["top_sensitive_imports"]:
            print(f"  {imp}: {count}")
    if report["top_sensitive_apis"]:
        print("\nTop sensitive APIs:")
        for api, count in report["top_sensitive_apis"]:
            print(f"  {api}: {count}")
    if report["reasons"]:
        print("\nReasons:")
        for reason in report["reasons"]:
            print(f"  - {reason}")
    if report.get("analysis_errors"):
        print("\nAnalysis notes/errors:")
        for err in report["analysis_errors"]:
            print(f"  - {err}")
    if report["snippets"]:
        print("\nExample suspicious snippets:")
        for snippet in report["snippets"][:2]:
            print("-" * 60)
            print(snippet[:1500])



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_PREDICT                                                     ┃
# ┃ CLI / PREDICT BASELINE                                                    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_predict(args: argparse.Namespace) -> int:
    """CLI: predict baseline.

    Có thể dùng heuristic mặc định hoặc logistic model đã train bằng lệnh train.
    Không dùng transformer encoder ở nhánh này nên chạy nhanh.
    """
    view = analyze_package(args.path)
    features = build_feature_dict(view)
    if args.model:
        model = FusionLogisticModel.from_json(json.loads(Path(args.model).read_text(encoding="utf-8")))
        probability = model.predict_proba(features)
        reasons = ["trained fusion classifier score"]
    else:
        probability, reasons = heuristic_probability(features)
    report = build_report(args.path, view, features, probability, reasons)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human_report(report)
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_TRAIN                                                       ┃
# ┃ CLI / TRAIN LOGISTIC MODEL                                                ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_train(args: argparse.Namespace) -> int:
    """CLI: train logistic baseline từ folder/file benign và malicious.

    Dữ liệu càng nhiều và càng đại diện thì model càng có ý nghĩa. Một vài mẫu
    nhỏ chỉ chứng minh pipeline train được, chưa chứng minh chất lượng thực tế.
    """
    samples: list[tuple[dict[str, float], int]] = []
    for path in args.benign:
        samples.append((build_feature_dict(analyze_package(path)), 0))
    for path in args.malicious:
        samples.append((build_feature_dict(analyze_package(path)), 1))
    if len(samples) < 2 or len({label for _, label in samples}) < 2:
        raise SystemExit("Need at least one benign and one malicious sample.")
    model = train_model(samples, epochs=args.epochs, lr=args.lr)
    out = Path(args.model)
    out.write_text(json.dumps(model.to_json(), indent=2), encoding="utf-8")
    print(f"Saved model: {out}")
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: WRITE_DEMO_PACKAGE                                              ┃
# ┃ FUNCTION / KHỐI XỬ LÝ WRITE_DEMO_PACKAGE                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 1 + FIG. 2: hàm demo này tự tạo package an toàn mô phỏng ví dụ trong paper.
# - FIG. 1: package malicious demo có __init__.py import cache_manager.py.
# - FIG. 2: metadata demo có trường UNKNOWN/thiếu để mô phỏng package đáng nghi.
def write_demo_package(root: Path, malicious: bool) -> Path:
    """Tạo package demo benign/malicious trong thư mục tạm.

    Package malicious ở đây là fixture an toàn: chứa bề mặt nghi ngờ để detector
    bắt được, nhưng không dùng cho tấn công thật.
    """
    pkg = root / ("evil_cache" if malicious else "clean_math")
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "PKG-INFO").write_text(textwrap.dedent(f"""\
        Metadata-Version: 2.1
        Name: {'seccache' if malicious else 'clean-math-tools'}
        Version: 0.0.3
        Summary: {'A fast cache helper' if malicious else 'Small arithmetic helpers'}
        Author: {'UNKNOWN' if malicious else 'Lizzy'}
        Author-email: {'UNKNOWN' if malicious else 'lizzy@example.local'}
        License: {'UNKNOWN' if malicious else 'MIT'}
        Home-page: {'None' if malicious else 'https://example.local/clean-math-tools'}
        Description: {'cache manager' if malicious else 'A harmless demo package for arithmetic helpers.'}
    """), encoding="utf-8")
    (pkg / "__init__.py").write_text("from .cache_manager import run\n" if malicious else "from .math_tools import add\n", encoding="utf-8")
    if malicious:
        (pkg / "cache_manager.py").write_text(textwrap.dedent("""\
            import base64
            import socket
            import subprocess

            def run():
                host = "127.0.0.1"
                port = 4444
                payload = base64.b64decode("cHJpbnQoJ2hlbGxvJyk=")
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                s.send(payload)
                subprocess.Popen(["cmd.exe", "/c", "whoami"])
        """), encoding="utf-8")
    else:
        (pkg / "math_tools.py").write_text(textwrap.dedent("""\
            def add(a, b):
                return a + b

            def mean(values):
                return sum(values) / len(values)
        """), encoding="utf-8")
    return pkg



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_DEMO                                                        ┃
# ┃ CLI / DEMO BENIGN VS MALICIOUS                                            ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_demo(args: argparse.Namespace) -> int:
    """CLI: chạy demo tự tạo để kiểm tra nhanh detector.

    Đây là smoke test tốt nhất sau khi sửa file: một package sạch phải thấp điểm,
    một package fixture đáng nghi phải cao điểm hơn.
    """
    with tempfile.TemporaryDirectory(prefix="mvrfdet_demo_") as td:
        root = Path(td)
        benign = write_demo_package(root, malicious=False)
        malicious = write_demo_package(root, malicious=True)
        for sample in (benign, malicious):
            view = analyze_package(sample)
            features = build_feature_dict(view)
            probability, reasons = heuristic_probability(features)
            print_human_report(build_report(str(sample), view, features, probability, reasons))
            print("\n" + "=" * 72 + "\n")
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_SENSITIVE_APIS                                              ┃
# ┃ CLI / RANK SENSITIVE API                                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_sensitive_apis(args: argparse.Namespace) -> int:
    """CLI: xếp hạng sensitive API xuất hiện trong các package.

    Hữu ích khi em muốn tự mở rộng danh sách API đáng nghi từ corpus của mình.
    """
    packages = [Path(p) for p in args.packages]
    centrality = Counter()
    for package in packages:
        view = analyze_package(package)
        stats = graph_stats(view.call_edges)
        for api, count in view.api_calls.items():
            boost = 3 if is_sensitive_call(api) else 1
            centrality[api] += count * boost + stats.get("graph_density", 0.0)
    for api, score in centrality.most_common(args.top):
        print(f"{api}\t{score:.3f}")
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: BUILD_ARG_PARSER                                                ┃
# ┃ HÀM / TẠO COMMAND LINE INTERFACE                                          ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def build_arg_parser() -> argparse.ArgumentParser:
    """Tạo CLI baseline ban đầu.

    Sau đó file có một build_arg_parser override ở cuối để thêm paper-predict,
    cache-models, env-check và train-neural.
    """
    parser = argparse.ArgumentParser(description="Single-file MVRFDet-inspired static malicious PyPI package detector.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("predict", help="Analyze one package directory, .py file, .zip, .tar, .tar.gz, or .whl.")
    p.add_argument("path")
    p.add_argument("--model", help="Optional trained JSON model.")
    p.add_argument("--json", action="store_true", help="Print JSON report.")
    p.set_defaults(func=cmd_predict)

    p = sub.add_parser("train", help="Train a small fusion logistic classifier from labeled package paths.")
    p.add_argument("--benign", nargs="+", required=True)
    p.add_argument("--malicious", nargs="+", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--epochs", type=int, default=80)
    p.add_argument("--lr", type=float, default=0.08)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("demo", help="Run a built-in benign vs malicious demo.")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("sensitive-apis", help="Rank candidate sensitive APIs from package paths.")
    p.add_argument("packages", nargs="+")
    p.add_argument("--top", type=int, default=100)
    p.set_defaults(func=cmd_sensitive_apis)
    return parser


# ---------------------------------------------------------------------------
# Paper-like extension: optional real MPNet/LongCoder encoders + NetworkX graph
# ---------------------------------------------------------------------------


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 07 / PAPER-LIKE FUSION                                               ║
# ║ 7. Paper-like Multi-View Representation Fusion                             ║
# ║                                                                            ║
# ║ Dựng 3 view thành matrix [metadata, code, graph] x 768.                    ║
# ║ Có thể dùng MPNet + LongCoder thật khi bật --real-encoders.                ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.3, PDF page 4: Metadata Encoder dùng all-mpnet-base-v2,
#   tạo V_m 768 chiều.
# - Paper: Section 3.4.2 và 3.4.3, PDF page 6: suspicious API snippets tối đa
#   4096 tokens được LongCoder encode thành V_c 768 chiều.
# - Paper: Section 3.4.4, PDF pages 6-7: Graph Encoder dùng 4-layer GAT cho API
#   call graph và CFG, rồi cross-selection fusion tạo V_g 1024 chiều.
# - Paper: Section 3.5, PDF page 7, Eq. 15-17: pad V_m/V_c từ 768 lên 1024,
#   L2-normalize từng view, reshape thành 32 x 32, stack thành F ∈ R^(3 x 32 x 32).
# - Source hiện tạo matrix [3, 768] để học/demo nhanh. Đây là "paper-like" nhưng
#   chưa đúng shape cuối của paper. Muốn sát paper hơn cần đổi thành [3, 32, 32].

# Đây là phần dựng gần kiến trúc paper nhất trong file.
#
# Paper nói MVRFDet fuse 3 view:
#   V_m = Metadata Feature
#   V_c = Code Feature
#   V_g = Graph Feature
#
# Bản này dựng lại cùng hình dạng dữ liệu:
#   matrix[0] = metadata vector 768 chiều
#   matrix[1] = code/context vector 768 chiều
#   matrix[2] = graph vector 768 chiều
#
# Nếu bật --real-encoders:
#   - Metadata dùng all-mpnet-base-v2.
#   - Code dùng microsoft/longcoder-base.
# Nếu không bật:
#   - Dùng dense hash fallback để vẫn giữ shape 3 x 768 và chạy nhanh.
PAPER_METADATA_MODEL = "sentence-transformers/all-mpnet-base-v2"
PAPER_CODE_MODEL = "microsoft/longcoder-base"
PAPER_EMBED_DIM = 768


# Fallback embedding ổn định. Không hiểu semantic như transformer, nhưng giúp
# biến token/string thành vector 768 chiều để demo và train-neural vẫn chạy ngay
# cả khi chưa tải model HuggingFace.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _DENSE_HASH                                                     ┃
# ┃ HÀM / FALLBACK EMBEDDING 768 CHIỀU                                        ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def _dense_hash(tokens, dim=PAPER_EMBED_DIM):
    """Tạo vector 768 chiều bằng feature hashing.

    Đây là fallback khi không dùng --real-encoders. Nó giữ đúng shape đầu vào cho
    fusion/CNN nhưng không có hiểu ngữ nghĩa như transformer.
    """
    vec = [0.0] * dim
    for token in tokens:
        if not token:
            continue
        idx = sha_bucket(str(token), dim)
        sign = 1.0 if sha_bucket("sign:" + str(token), 2) == 0 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _TEXT_DENSE_HASH                                                ┃
# ┃ FUNCTION / KHỐI XỬ LÝ _TEXT_DENSE_HASH                                    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def _text_dense_hash(text, dim=PAPER_EMBED_DIM):
    """Tokenize rất nhẹ rồi gọi _dense_hash.

    Dùng cho metadata/code fallback để paper-predict vẫn chạy nhanh và offline.
    """
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}|https?://[^\s'\"<>]+|[0-9a-fA-F]{16,}", (text or "").lower())
    return _dense_hash(tokens, dim)


# Mean pooling cho transformer: lấy trung bình embedding token, bỏ qua padding.
# Đây là cách đơn giản để biến nhiều token thành một vector đại diện cho cả text.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _MEAN_POOL_TORCH                                                ┃
# ┃ FUNCTION / KHỐI XỬ LÝ _MEAN_POOL_TORCH                                    ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def _mean_pool_torch(last_hidden_state, attention_mask):
    """Pool output transformer thành một vector duy nhất.

    Padding token bị mask ra, nên vector cuối đại diện cho nội dung thật hơn.
    """
    import torch
    mask = attention_mask.unsqueeze(-1).expand(last_hidden_state.size()).float()
    return torch.sum(last_hidden_state * mask, dim=1) / torch.clamp(mask.sum(dim=1), min=1e-9)


# ──────────────────────────────────────────────────────────────────────────
# │ ENCODER V_m :: 7.1 Metadata Encoder                                    │
# │ MPNet hoặc dense-hash fallback cho metadata.                           │

# ──────────────────────────────────────────────────────────────────────────

# Khi dùng --real-encoders, metadata text được đưa qua all-mpnet-base-v2 để lấy
# embedding semantic. Đây là kênh V_m trong sơ đồ paper.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _ENCODE_METADATA_REAL                                           ┃
# ┃ HÀM / GỌI MPNET CHO METADATA                                              ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Metadata Encoder.
# Hàm này encode V_m bằng all-mpnet-base-v2 khi bật --real-encoders.
def _encode_metadata_real(text):
    """Encode metadata bằng all-mpnet-base-v2.

    Đây là kênh semantic cho Metadata View. Model được tải/cache bởi thư viện
    sentence-transformers và chạy local trên máy em.
    """
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer(PAPER_METADATA_MODEL)
    emb = model.encode([text or " "], normalize_embeddings=True, show_progress_bar=False)[0]
    return [float(x) for x in emb.tolist()], PAPER_METADATA_MODEL


# ──────────────────────────────────────────────────────────────────────────
# │ ENCODER V_c :: 7.2 Code Encoder                                        │
# │ LongCoder hoặc dense-hash fallback cho code/snippet.                   │

# ──────────────────────────────────────────────────────────────────────────

# Khi dùng --real-encoders, code/snippet được đưa qua microsoft/longcoder-base.
# LongCoder phù hợp hơn model text thường vì xử lý source code dài tốt hơn.
# Đây là kênh V_c trong sơ đồ paper.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _ENCODE_CODE_REAL                                               ┃
# ┃ HÀM / GỌI LONGCODER CHO CODE                                              ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Code Encoder.
# Hàm này encode V_c bằng microsoft/longcoder-base khi bật --real-encoders.
def _encode_code_real(text):
    """Encode code/snippet bằng microsoft/longcoder-base.

    LongCoder được dùng như code encoder gần tinh thần paper hơn text encoder
    thường. Hàm này không chạy code, chỉ đưa source text vào transformer.
    """
    import torch
    import torch.nn.functional as F
    from transformers import AutoModel, AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(PAPER_CODE_MODEL)
    model = AutoModel.from_pretrained(PAPER_CODE_MODEL)
    model.eval()
    encoded = tokenizer(text or " ", padding=True, truncation=True, max_length=4096, return_tensors="pt")
    with torch.no_grad():
        output = model(**encoded)
        pooled = _mean_pool_torch(output.last_hidden_state, encoded["attention_mask"])
        pooled = F.normalize(pooled, p=2, dim=1)
    return [float(x) for x in pooled[0].cpu().tolist()], PAPER_CODE_MODEL


# ──────────────────────────────────────────────────────────────────────────
# │ ENCODER V_g :: 7.3 Graph Encoder                                       │
# │ NetworkX graph features chiếu về vector 768 chiều.                     │

# ──────────────────────────────────────────────────────────────────────────

# Paper dùng graph representation. Bản này dựng graph thực dụng bằng NetworkX:
#   - node/cạnh lấy từ caller -> callee
#   - PageRank/degree phản ánh API/function nào trung tâm
#   - CFG counters phản ánh độ phức tạp điều khiển
# Sau đó chiếu thành vector 768 chiều để cùng shape với metadata/code.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _GRAPH_DENSE_NETWORKX                                           ┃
# ┃ HÀM / ENCODE GRAPH BẰNG NETWORKX                                          ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Graph Encoder.
# Hàm này dựng V_g từ call graph/CFG bằng NetworkX rồi chiếu về 768 chiều.
def _graph_dense_networkx(view, dim=PAPER_EMBED_DIM):
    """Encode graph bằng NetworkX + hashing projection.

    Bản này không có graph neural network chính chủ, nên dùng PageRank/degree và
    CFG counters làm graph representation thực dụng cho V_g.
    """
    try:
        import networkx as nx
        graph = nx.DiGraph()
        for (src, dst), weight in view.call_edges.items():
            graph.add_edge(src, dst, weight=weight)
        if graph.number_of_nodes() == 0:
            return [0.0] * dim, "networkx-empty"
        pagerank = nx.pagerank(graph, weight="weight", max_iter=100)
        degree = dict(graph.degree(weight="weight"))
        tokens = []
        for node in sorted(graph.nodes()):
            repeat = int(min(20, 1 + degree.get(node, 0) + pagerank.get(node, 0.0) * 100))
            if is_sensitive_call(node):
                repeat += 4
            tokens.extend([node] * repeat)
        for src, dst in graph.edges():
            tokens.append(f"{src}->{dst}")
        return _dense_hash(tokens, dim), "networkx pagerank/degree graph embedding"
    except Exception as exc:
        tokens = []
        for (src, dst), count in view.call_edges.items():
            tokens.extend([f"{src}->{dst}"] * min(count, 5))
        return _dense_hash(tokens, dim), f"fallback graph hash ({exc.__class__.__name__})"


# Tạo input fusion đúng dạng 3 x 768:
#   hàng 0: Metadata View  (V_m)
#   hàng 1: Code View      (V_c)
#   hàng 2: Graph View     (V_g)
# Matrix này là thứ được đưa vào channel attention và CNN prototype.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: BUILD_PAPER_LIKE_MATRIX                                         ┃
# ┃ HÀM / TẠO MATRIX 3 X 768                                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Feature Matrix Generation.
# Hàm này tạo ma trận 3 x 768 gồm: hàng 0 metadata, hàng 1 code, hàng 2 graph.
def build_paper_like_matrix(view, real_encoders=False):
    """Tạo ma trận fusion [3, 768].

    Đây là điểm nối quan trọng nhất của paper-like mode: mọi view được đưa về
    cùng số chiều để attention/CNN có thể xử lý như 3 channel.
    """
    metadata_text = "\n".join(f"{k}: {v}" for k, v in sorted(view.metadata.items()))
    code_text = "\n\n".join(view.suspicious_snippets[:MAX_SNIPPETS])
    notes = []
    if real_encoders:
        try:
            meta_vec, name = _encode_metadata_real(metadata_text)
            notes.append(f"metadata encoder: {name}")
        except Exception as exc:
            meta_vec = _text_dense_hash(metadata_text)
            notes.append(f"metadata encoder fallback: dense hash ({exc.__class__.__name__}: {exc})")
        try:
            code_vec, name = _encode_code_real(code_text)
            notes.append(f"code encoder: {name}")
        except Exception as exc:
            code_vec = _text_dense_hash(code_text)
            notes.append(f"code encoder fallback: dense hash ({exc.__class__.__name__}: {exc})")
    else:
        meta_vec = _text_dense_hash(metadata_text)
        code_vec = _text_dense_hash(code_text)
        notes.append("metadata encoder: dense hash fallback")
        notes.append("code encoder: dense hash fallback")
    graph_vec, graph_note = _graph_dense_networkx(view)
    notes.append(f"graph encoder: {graph_note}")
    return [meta_vec[:PAPER_EMBED_DIM], code_vec[:PAPER_EMBED_DIM], graph_vec[:PAPER_EMBED_DIM]], notes


# Channel Attention Fusion:
# Tính trọng số cho từng kênh metadata/code/graph dựa trên năng lượng vector.
# Ý tưởng: view nào có tín hiệu mạnh hơn thì có thể được chú ý nhiều hơn khi fuse.











# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _CHANNEL_ATTENTION                                              ┃
# ┃ HÀM / TÍNH ATTENTION CHO 3 VIEW                                           ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Channel Attention Fusion.
# Hàm này tính trọng số cho 3 channel Metadata/Code/Graph trước khi fuse.
def _channel_attention(matrix):
    """Tính trọng số attention cho 3 channel.

    Output luôn có 3 số tổng bằng 1, lần lượt cho metadata/code/graph. Bản này
    dùng năng lượng vector làm tín hiệu chú ý đơn giản.
    """
    energies = [math.sqrt(sum(v * v for v in channel)) for channel in matrix]
    if not any(energies):
        return [1.0 / len(matrix)] * len(matrix)
    top = max(energies)
    exps = [math.exp(e - top) for e in energies]
    total = sum(exps) or 1.0
    return [e / total for e in exps]


# Dự đoán theo mode paper-like:
#   1. Lấy base score từ heuristic feature.
#   2. Tính attention cho 3 view.
#   3. Fuse metadata/code/graph signal thành xác suất cuối.
# Đây vẫn là prototype scoring, không phải classifier gốc của paper.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: _PAPER_LIKE_PROBABILITY                                         ┃
# ┃ HÀM / FUSE 3 VIEW RA XÁC SUẤT                                             ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: Classification sau fusion.
# Hàm này blend tín hiệu 3 view để ra malicious_probability ở cuối pipeline.
def _paper_like_probability(features, matrix):
    """Fuse heuristic score với attention-weighted 3-view signals.

    Hàm này là cầu nối giữa feature_dict dễ giải thích và matrix 3 x 768 giống
    kiến trúc paper.
    """
    base, reasons = heuristic_probability(features)
    att = _channel_attention(matrix)
    metadata_signal = features.get("meta_missing_ratio", 0.0) + features.get("meta_suspicious_words", 0.0)
    code_signal = features.get("sensitive_api_total", 0.0) + features.get("snippet_suspicious_words", 0.0)
    graph_signal = features.get("graph_edges", 0.0) + features.get("cfg_edges", 0.0)
    fused = 0.40 * base
    fused += 0.20 * att[0] * sigmoid(2.5 * metadata_signal)
    fused += 0.25 * att[1] * sigmoid(3.5 * code_signal)
    fused += 0.15 * att[2] * sigmoid(2.5 * graph_signal)
    reasons.append(f"channel attention weights metadata/code/graph = {att[0]:.2f}/{att[1]:.2f}/{att[2]:.2f}")
    return min(max(fused, 0.0), 1.0), reasons



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_PAPER_PREDICT                                               ┃
# ┃ CLI / PAPER-LIKE PREDICT                                                  ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: CLI chạy toàn bộ pipeline paper-like từ package -> 3 view -> fusion -> output.
def cmd_paper_predict(args):
    """CLI: chạy paper-like 3-view fusion prediction.

    Thêm --real-encoders để gọi MPNet/LongCoder thật. Không thêm flag đó thì dùng
    dense hash fallback để chạy nhanh.
    """
    view = analyze_package(args.path)
    features = build_feature_dict(view)
    matrix, notes = build_paper_like_matrix(view, real_encoders=args.real_encoders)
    probability, reasons = _paper_like_probability(features, matrix)
    report = build_report(args.path, view, features, probability, reasons)
    report["mode"] = "paper-like"
    report["encoders"] = notes
    report["feature_matrix_shape"] = [len(matrix), len(matrix[0]) if matrix else 0]
    report["channel_attention"] = [round(x, 4) for x in _channel_attention(matrix)]
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human_report(report)
        print("\nPaper-like mode:")
        for note in notes:
            print(f"  - {note}")
        print(f"  - feature matrix shape: {report['feature_matrix_shape']}")
        print(f"  - channel attention: {report['channel_attention']}")
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_CACHE_MODELS                                                ┃
# ┃ CLI / CACHE HUGGINGFACE MODELS                                            ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_cache_models(args):
    """CLI: tải/cache model HuggingFace dùng cho --real-encoders.

    Chạy lệnh này trước giúp lần predict sau nhanh hơn và ít phụ thuộc mạng hơn.
    """
    print("Caching metadata encoder:", PAPER_METADATA_MODEL)
    _encode_metadata_real("Name: demo\nSummary: harmless package")
    if not args.metadata_only:
        print("Caching code encoder:", PAPER_CODE_MODEL)
        _encode_code_real("import socket\nsocket.socket()")
    print("Done.")
    return 0



# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_ENV_CHECK                                                   ┃
# ┃ CLI / CHECK THƯ VIỆN                                                      ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def cmd_env_check(args):
    """CLI: kiểm tra thư viện tùy chọn.

    In version của torch, transformers, sentence-transformers, networkx, sklearn,
    scalpel và trạng thái CUDA.
    """
    mods = ["torch", "transformers", "sentence_transformers", "networkx", "sklearn", "scalpel"]
    out = {}
    for mod in mods:
        try:
            imported = __import__(mod)
            out[mod] = getattr(imported, "__version__", "installed")
        except Exception as exc:
            out[mod] = f"missing or failed: {exc.__class__.__name__}: {exc}"
    try:
        import torch
        out["torch_cuda_available"] = torch.cuda.is_available()
    except Exception:
        out["torch_cuda_available"] = False
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 08 / CNN + ATTENTION                                                 ║
# ║ 8. CNN + Channel Attention training                                        ║
# ║                                                                            ║
# ║ PyTorch CNN học trên input [batch, 3, 768].                                ║
# ║ Channel attention học trọng số cho metadata/code/graph.                    ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper: Section 3.5 "Feature matrix generation and channel attention fusion
#   classification", PDF page 7.
# - Paper: Fig. 7, PDF page 7: input là feature matrix F ∈ R^(3 x 32 x 32), đi
#   qua 3 convolution layers và 3 max-pooling layers.
# - Paper: Eq. 18, PDF page 7: Channel Attention dùng MaxPool(F') và AvgPool(F'),
#   đưa qua shared MLP rồi sigmoid để tạo attention vector M.
# - Paper: Eq. 19, PDF page 7: output classification là Softmax(MLP(F' * M));
#   MLP có 2 linear layers 4096 và 2 neurons.
# - Source hiện dùng Tiny Conv1d trên [batch, 3, 768] với attention nhỏ. Nó chứng
#   minh ý tưởng CNN + attention train được, nhưng chưa phải CNN/CAM/MLP đúng Fig. 7.

# Đây là nhánh neural prototype gần paper hơn baseline logistic.
# Input: tensor [batch, 3, 768]
#   - 3 là số view/channel: metadata, code, graph
#   - 768 là chiều embedding mỗi view
#
# Kiến trúc nhỏ:
#   Conv1d -> ReLU -> Conv1d -> ReLU -> Conv1d -> ReLU
#   Channel attention học trọng số cho 3 view
#   MLP head xuất logit malicious/benign
# FIG. 3: CNN Classification + Channel Attention prototype.
# Class này tạo model PyTorch học trực tiếp trên feature matrix [batch, 3, 768].
class _TinyMVRFNetFactory:
    """Factory tạo PyTorch CNN + channel-attention model.

    Đặt trong factory để import torch lười hơn: chỉ cần torch khi train neural,
    còn các lệnh static nhẹ không phải khởi động PyTorch ngay từ đầu.
    """
    @staticmethod

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CREATE                                                          ┃
# ┃ FUNCTION / KHỐI XỬ LÝ CREATE                                              ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    def create():
        import torch
        import torch.nn as nn

        class TinyMVRFNet(nn.Module):
            def __init__(self):
                super().__init__()
                self.conv = nn.Sequential(
                    nn.Conv1d(3, 16, kernel_size=5, padding=2), nn.ReLU(),
                    nn.Conv1d(16, 32, kernel_size=5, padding=2), nn.ReLU(),
                    nn.Conv1d(32, 32, kernel_size=3, padding=1), nn.ReLU(),
                )
                self.channel_attention = nn.Sequential(nn.Linear(3, 8), nn.ReLU(), nn.Linear(8, 3), nn.Sigmoid())
                self.head = nn.Sequential(nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 2))

            def forward(self, x):
                energy = torch.sqrt(torch.clamp((x * x).sum(dim=2), min=1e-9))
                weights = self.channel_attention(energy).unsqueeze(-1)
                x = self.conv(x * weights).mean(dim=2)
                return self.head(x)

        return TinyMVRFNet()


# Lệnh train-neural:
#   python mvrfdet_single_file.py train-neural --benign good1 good2 #       --malicious bad1 bad2 --model mvrfdet_tiny.pt
#
# Nếu thêm --real-encoders, dữ liệu train dùng MPNet + LongCoder thật, nhưng sẽ
# chậm hơn đáng kể trên CPU.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: CMD_TRAIN_NEURAL                                                ┃
# ┃ CLI / TRAIN CNN + CHANNEL ATTENTION                                       ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
# FIG. 3: lệnh train CNN + channel attention cho classifier cuối.
# Đây là phần gần khối Channel Attention Fusion Classification nhất trong code.
def cmd_train_neural(args):
    """CLI: train CNN + channel attention trên feature matrix 3 x 768.

    Đây là nhánh neural thật bằng PyTorch. Với ít sample, nó chỉ chứng minh code
    train được; muốn đánh giá nghiêm túc cần dataset lớn và chia train/test.
    """
    import torch
    import torch.nn as nn

    matrices = []
    labels = []
    for path in args.benign:
        matrices.append(build_paper_like_matrix(analyze_package(path), real_encoders=args.real_encoders)[0])
        labels.append(0)
    for path in args.malicious:
        matrices.append(build_paper_like_matrix(analyze_package(path), real_encoders=args.real_encoders)[0])
        labels.append(1)
    if len(set(labels)) < 2:
        raise SystemExit("Need at least one benign and one malicious sample.")
    x = torch.tensor(matrices, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)
    net = _TinyMVRFNetFactory.create()
    opt = torch.optim.Adam(net.parameters(), lr=args.lr)
    loss_fn = nn.CrossEntropyLoss()
    for epoch in range(args.epochs):
        opt.zero_grad()
        loss = loss_fn(net(x), y)
        loss.backward()
        opt.step()
    torch.save({"state_dict": net.state_dict(), "version": VERSION, "real_encoders": args.real_encoders}, args.model)
    print(f"Saved neural CNN+CAM model: {args.model}")
    return 0


_legacy_build_arg_parser = build_arg_parser


# ══════════════════════════════════════════════════════════════════════════════
# ║                                                                            ║
# ║ STAGE 09 / CLI ROUTER                                                      ║
# ║ 9. Command Line Interface                                                  ║
# ║                                                                            ║
# ║ Gắn các command demo, predict, paper-predict, train, train-neural.         ║
# ║ Đây là lớp người dùng gọi từ PowerShell.                                   ║
# ║                                                                            ║

# ══════════════════════════════════════════════════════════════════════════════

# PAPER CROSS-REFERENCE / ĐỐI CHIẾU PAPER
# - Paper không có CLI router; đây là lớp tiện ích của source để em gọi pipeline
#   từ PowerShell bằng demo/predict/paper-predict/train/train-neural.
# - Liên quan tới Section 4 "Evaluation and results", PDF pages 8-11: các lệnh
#   train/predict là nền để sau này dựng evaluation, nhưng hiện chưa có đầy đủ
#   dataset 10,190 malicious + 10,000 benign, 5-fold CV, 8 baselines, ablation,
#   efficiency benchmark và hyperparameter sensitivity như paper.
# - Khi đối chiếu: stage này không phải kiến trúc MVRFDet, mà là interface để
#   chạy bản dựng lại an toàn trên máy local.

# Các lệnh chính:
#   demo             chạy demo benign/malicious tự tạo
#   predict          phân tích bằng baseline heuristic/logistic
#   paper-predict    phân tích bằng 3-view fusion matrix
#   cache-models     tải/cache MPNet + LongCoder
#   env-check        kiểm tra thư viện phụ trợ
#   train            train logistic baseline
#   train-neural     train CNN + channel attention
#
# Hàm này override parser ban đầu để gắn thêm các lệnh paper-like extension.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: BUILD_ARG_PARSER                                                ┃
# ┃ HÀM / TẠO COMMAND LINE INTERFACE                                          ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def build_arg_parser():
    """Tạo CLI cuối cùng cho toàn bộ file.

    Hàm này gọi parser baseline rồi gắn thêm các command paper-like extension.
    """
    parser = _legacy_build_arg_parser()
    sub = parser._subparsers._group_actions[0]

    p = sub.add_parser("paper-predict", help="Analyze with paper-like 3x768 matrix; optionally use real MPNet/LongCoder encoders.")
    p.add_argument("path")
    p.add_argument("--real-encoders", action="store_true", help="Use all-mpnet-base-v2 and microsoft/longcoder-base when available/downloadable.")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_paper_predict)

    p = sub.add_parser("cache-models", help="Download/cache the HuggingFace encoders used by paper-like mode.")
    p.add_argument("--metadata-only", action="store_true", help="Only cache all-mpnet-base-v2, skip LongCoder.")
    p.set_defaults(func=cmd_cache_models)

    p = sub.add_parser("env-check", help="Check installed optional dependencies.")
    p.set_defaults(func=cmd_env_check)

    p = sub.add_parser("train-neural", help="Train a tiny PyTorch CNN + channel attention classifier on labeled package paths.")
    p.add_argument("--benign", nargs="+", required=True)
    p.add_argument("--malicious", nargs="+", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--epochs", type=int, default=80)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--real-encoders", action="store_true")
    p.set_defaults(func=cmd_train_neural)
    return parser


# Entry point cuối cùng. Các lỗi người dùng hay gặp như nhập sai đường dẫn sẽ
# được in gọn, thay vì quăng traceback dài khó đọc.

# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
# ┃ FUNCTION: MAIN                                                            ┃
# ┃ HAM / ENTRY POINT                                                         ┃
# ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
def main(argv: list[str] | None = None) -> int:
    """Entry point của chương trình.

    Bắt lỗi path/input thường gặp để người dùng thấy thông báo ngắn gọn thay vì
    traceback dài. Cuối file dùng os._exit để tránh worker nền của model làm treo
    terminal sau khi đã in xong output.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    exit_code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)







