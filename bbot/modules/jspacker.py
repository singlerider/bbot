import regex as re
import mmh3
from .base import BaseModule

PACKER_SIGNATURE = "}('"
PACKER_PATTERN = re.compile(
    r"\}\s*\(\s*'(?P<payload>(?:\\.|[^'\\])*)'\s*,\s*"
    r"(?P<radix>\d+)\s*,\s*"
    r"(?P<count>\d+)\s*,\s*"
    r"'(?P<keywords>(?:\\.|[^'\\])*)'\.split\('\|'\)",
    re.DOTALL,
)
BASE_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORD_PATTERN = re.compile(r"\b\w+\b")


def encode_token(index, radix):
    prefix = "" if index < radix else encode_token(index // radix, radix)
    remainder = index % radix
    if remainder > 35:
        return prefix + chr(remainder + 29)
    return prefix + BASE_DIGITS[remainder]


def build_lookup(keywords, radix, count):
    lookup = {}
    for index in range(count):
        token = encode_token(index, radix)
        keyword = keywords[index] if index < len(keywords) and keywords[index] else token
        lookup[token] = keyword
    return lookup


def unpack_payload(match):
    payload = match.group("payload").encode().decode("unicode_escape")
    radix = int(match.group("radix"))
    count = int(match.group("count"))
    keywords = match.group("keywords").split("|")
    lookup = build_lookup(keywords, radix, count)
    return WORD_PATTERN.sub(lambda token: lookup.get(token.group(0), token.group(0)), payload)


def unpack(text):
    unpacked = []
    for match in PACKER_PATTERN.finditer(text):
        try:
            unpacked.append(unpack_payload(match))
        except (ValueError, UnicodeDecodeError):
            continue
    return unpacked


class jspacker(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["HTTP_RESPONSE"]
    flags = ["passive", "safe", "web"]
    meta = {
        "description": "Unpack Dean Edwards (p,a,c,k,e,d) packed JavaScript and re-emit the response so other modules can analyze the revealed content",
        "created_date": "2026-06-23",
        "author": "@singlerider",
    }

    deobfuscated_tag = "js-unpacked"

    async def filter_event(self, event):
        if self.deobfuscated_tag in event.tags:
            return False, "event was already unpacked by this module"
        if PACKER_SIGNATURE not in (event.body or ""):
            return False, "response body contains no packed JavaScript"
        return True

    async def handle_event(self, event):
        body = event.body
        if not body:
            return
        unpacked_segments = unpack(body)
        if not unpacked_segments:
            return
        revealed = "\n".join(unpacked_segments)
        if revealed in body:
            return
        data = dict(event.data)
        data.pop("header-dict", None)
        merged_body = f"{body}\n{revealed}"
        data["body"] = merged_body
        if isinstance(data.get("hash"), dict):
            data["hash"] = dict(data["hash"])
            data["hash"]["body_mmh3"] = mmh3.hash(merged_body)
        unpacked_event = self.make_event(
            data,
            "HTTP_RESPONSE",
            parent=event,
            tags=[self.deobfuscated_tag],
            context="{module} unpacked packed JavaScript in {event.parent.type} and re-emitted it for analysis",
        )
        if unpacked_event is None:
            return
        unpacked_event.scope_distance = event.scope_distance
        await self.emit_event(unpacked_event)
