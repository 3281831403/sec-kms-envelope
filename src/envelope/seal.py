"""多租户信封加密的核心实现。

主密钥使用映射表示，包含以下字段：

    root      根密钥材料，bytes
    versions  当前仍可用的版本标识序列
    current   新封装默认使用的版本
    retired   已停用的版本标识序列

封装结果是映射，包含 header 与 ciphertext 两个键。header 的字段如下：

    version  主密钥版本标识
    key_id   数据密钥标识
    tenant   请求方标识
    alg      内容加密算法
    nonce    Base64 编码的 12 字节随机数
    digest   头部摘要

ciphertext 是 Base64 编码的密文与认证标签。数据密钥由根密钥材料、版本与
租户共同派生，附加认证数据覆盖版本、请求方与密钥标识，头部摘要覆盖除
digest 以外的全部头部字段。解封失败统一抛出 EnvelopeError。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
VERSION_MAX = 16
KEY_ID_MAX = 64
TENANT_MAX = 64
ALG = "AES-256-GCM"
INVALID_MESSAGE = "invalid sealed message"

# 参与头部摘要认证的字段（digest 自身除外）。
_HEADER_FIELDS = ("version", "key_id", "tenant", "alg", "nonce")


class EnvelopeError(Exception):
    """信封处理失败时抛出的统一错误。"""


class AuthenticationError(EnvelopeError):
    """认证标签校验失败。

    保留该类型仅为向后兼容；解封路径上的任何失败都统一抛出
    EnvelopeError，不向调用方暴露失败发生在哪一步。
    """


def _pack(text: str) -> bytes:
    raw = text.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("encoded value must be text")
    return base64.b64decode(text.encode("ascii"), validate=True)


def _new_nonce() -> bytes:
    """每次封装生成全新的随机 nonce，保证重复封装结果不同。"""
    return os.urandom(NONCE_SIZE)


def _key_id(master: dict, version: str, tenant: str) -> str:
    material = (
        b"envelope/key-id/v1"
        + master["root"]
        + _pack(version)
        + _pack(tenant)
    )
    return "k-" + hashlib.sha256(material).hexdigest()[:16]


def _header_digest(header: dict) -> str:
    """对除 digest 以外的全部头部字段做确定性序列化后摘要。

    任一字段变化都会改变摘要；头部多出的额外字段也会改变摘要。
    """
    payload = json.dumps(
        {field: header.get(field, "") for field in _HEADER_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def derive_data_key(master: dict, version: str, tenant: str) -> bytes:
    """派生数据密钥。

    数据密钥必须与主密钥版本和租户绑定，同一根密钥下的不同版本、不同
    租户都不得得到相同的数据密钥。各输入带长度前缀，避免拼接歧义。
    """
    material = (
        b"envelope/data-key/v1"
        + _pack(version)
        + _pack(tenant)
    )
    return hmac.new(master["root"], material, hashlib.sha256).digest()


def build_aad(version: str, tenant: str, key_id: str) -> bytes:
    """构造附加认证数据。

    返回的字节串必须唯一对应版本、请求方与密钥标识三者，任一字段变化都
    必须改变结果。各输入带长度前缀，避免拼接歧义。
    """
    return (
        b"envelope/aad/v1"
        + _pack(version)
        + _pack(tenant)
        + _pack(key_id)
    )


def check_version(master: dict, version: str) -> bool:
    """判断主密钥版本是否仍可用。"""
    if not isinstance(version, str) or not version:
        return False
    versions = master.get("versions") or ()
    retired = master.get("retired") or ()
    return version in versions and version not in retired


def validate_header(header: dict) -> list:
    """返回头部的问题列表，没有问题时返回空列表。

    头部必须且只能包含约定的字段；每个字段都必须是非空字符串，长度
    受限；nonce 必须能解码为约定长度的随机数。
    """
    if not isinstance(header, dict):
        return ["header must be a mapping"]
    problems = []
    required = list(_HEADER_FIELDS) + ["digest"]
    if set(header) != set(required):
        problems.append("header fields mismatch")
        return problems
    limits = {
        "version": VERSION_MAX,
        "key_id": KEY_ID_MAX,
        "tenant": TENANT_MAX,
        "alg": len(ALG),
        "nonce": 64,
        "digest": 64,
    }
    for field in required:
        value = header.get(field)
        if not isinstance(value, str) or not value:
            problems.append("missing or invalid " + field)
            continue
        if len(value) > limits[field]:
            problems.append(field + " too long")
    if problems:
        return problems
    try:
        nonce = _b64d(header["nonce"])
    except (binascii.Error, ValueError, UnicodeError):
        problems.append("invalid nonce encoding")
        return problems
    if len(nonce) != NONCE_SIZE:
        problems.append("nonce length mismatch")
    return problems


def _build_header(master: dict, nonce: bytes, tenant: str, version: str) -> dict:
    header = {
        "version": version,
        "key_id": _key_id(master, version, tenant),
        "tenant": tenant,
        "alg": ALG,
        "nonce": _b64e(nonce),
    }
    header["digest"] = _header_digest(header)
    return header


def _seal_with_key(
    master: dict,
    key: bytes,
    plaintext: bytes,
    tenant: str,
    version: str,
) -> dict:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise EnvelopeError(INVALID_MESSAGE)
    nonce = _new_nonce()
    header = _build_header(master, nonce, tenant, version)
    aad = build_aad(version, tenant, header["key_id"])
    ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), aad)
    return {"header": header, "ciphertext": _b64e(ciphertext)}


def seal(master: dict, plaintext: bytes, tenant: str, version: str) -> dict:
    """封装明文，返回包含头部与密文的映射。"""
    if not isinstance(tenant, str) or not tenant or len(tenant) > TENANT_MAX:
        raise EnvelopeError(INVALID_MESSAGE)
    if not isinstance(version, str) or not version or len(version) > VERSION_MAX:
        raise EnvelopeError(INVALID_MESSAGE)
    # 封装时同样校验版本，停用或未知版本不得产生新密文。
    if not check_version(master, version):
        raise EnvelopeError(INVALID_MESSAGE)
    key = derive_data_key(master, version, tenant)
    return _seal_with_key(master, key, plaintext, tenant, version)


def open_sealed(master: dict, sealed: dict, tenant: str) -> bytes:
    """解封，返回原文。

    头部结构、版本可用性、头部摘要和认证标签都必须校验通过；任何失败
    都抛出同一种 EnvelopeError，不暴露失败发生在哪一步。
    """
    try:
        if not isinstance(sealed, dict):
            raise EnvelopeError(INVALID_MESSAGE)
        header = sealed.get("header")
        problems = validate_header(header)
        if problems:
            raise EnvelopeError(INVALID_MESSAGE)
        if not isinstance(tenant, str) or not tenant:
            raise EnvelopeError(INVALID_MESSAGE)

        version = header["version"]
        key_id = header["key_id"]
        header_tenant = header["tenant"]

        # 头部声明的版本必须仍然可用（未停用、仍在版本列表中）。
        if not check_version(master, version):
            raise EnvelopeError(INVALID_MESSAGE)
        # 请求方必须与头部声明的租户一致，防止跨租户解封。
        if not hmac.compare_digest(header_tenant, tenant):
            raise EnvelopeError(INVALID_MESSAGE)
        # 头部每个字段都参与认证：先校验头部摘要。
        if not hmac.compare_digest(header["digest"], _header_digest(header)):
            raise EnvelopeError(INVALID_MESSAGE)

        # 数据密钥由根密钥 + 版本 + 租户共同派生，与头部中的 key_id
        # 必须一致；key_id 也进入 AAD，随认证标签再次绑定。
        key = derive_data_key(master, version, tenant)
        expected_key_id = _key_id(master, version, tenant)
        if not hmac.compare_digest(key_id, expected_key_id):
            raise EnvelopeError(INVALID_MESSAGE)

        nonce = _b64d(header["nonce"])
        if len(nonce) != NONCE_SIZE:
            raise EnvelopeError(INVALID_MESSAGE)
        ciphertext = _b64d(sealed["ciphertext"])

        # AAD 覆盖版本、请求方与密钥标识，任一字段被改动都会认证失败。
        aad = build_aad(version, tenant, key_id)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except EnvelopeError:
        raise
    except (InvalidTag, binascii.Error, ValueError, UnicodeError, KeyError, TypeError):
        # 统一错误类型与文案，不泄露失败发生在哪一步。
        raise EnvelopeError(INVALID_MESSAGE) from None


def rotate_master(old: dict, new: dict, sealed_items: dict) -> dict:
    """主密钥轮换，返回重新封装后的条目。

    每个条目都要用旧主密钥解开，再用新主密钥的当前版本重新封装，返回的
    映射与输入保持相同的键。每条独立处理，键顺序与输入保持一致。
    """
    rotated = {}
    new_version = new.get("current", "v1")
    for label, sealed in sealed_items.items():
        header = sealed.get("header") if isinstance(sealed, dict) else None
        if not isinstance(header, dict):
            raise EnvelopeError(INVALID_MESSAGE)
        tenant = header.get("tenant", "")
        plaintext = open_sealed(old, sealed, tenant)
        rotated[label] = seal(new, plaintext, tenant, new_version)
    return rotated


def envelope_batch(items, tenant: str) -> dict:
    """批量加解，返回 results 与 errors 两个映射。

    items 中每项包含 id、master，以及 plaintext 与 version（封装）或
    sealed（解封）之一。每一条独立处理：各自派生数据密钥、各自生成
    随机 nonce，单条失败只记入 errors，不影响其他条目。
    """
    results = {}
    errors = {}
    for index, item in enumerate(items):
        name = str(item.get("id", "item-" + str(index)))
        try:
            master = item["master"]
            if "sealed" in item:
                results[name] = open_sealed(master, item["sealed"], tenant)
            else:
                version = item["version"]
                # 走公开的 seal：每条独立校验版本、独立派生数据密钥并
                # 生成随机 nonce，禁止跨条目、跨租户、跨主密钥复用。
                results[name] = seal(master, item["plaintext"], tenant, version)
        except Exception:
            # 只记录统一的失败信息，不暴露内部步骤与异常类型。
            errors[name] = INVALID_MESSAGE
    return {"results": results, "errors": errors}
