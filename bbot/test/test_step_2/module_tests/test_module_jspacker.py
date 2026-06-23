import re

from .base import ModuleTestBase

BASE_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def encode_token(index, radix):
    prefix = "" if index < radix else encode_token(index // radix, radix)
    remainder = index % radix
    if remainder > 35:
        return prefix + chr(remainder + 29)
    return prefix + BASE_DIGITS[remainder]


def pack(source):
    keywords = []
    for word in re.findall(r"\b\w+\b", source):
        if word not in keywords:
            keywords.append(word)
    radix = max(2, len(keywords))
    index = {word: position for position, word in enumerate(keywords)}
    payload = re.sub(r"\b\w+\b", lambda match: encode_token(index[match.group(0)], radix), source)
    payload = payload.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    return (
        "eval(function(p,a,c,k,e,d){e=function(c){return(c<a?'':e(parseInt(c/a)))+"
        "((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String))"
        "{while(c--)d[e(c)]=k[c]||e(c);k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};"
        "while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}"
        f"('{payload}',{radix},{len(keywords)},'{'|'.join(keywords)}'.split('|'),0,{{}}))"
    )


class TestJSPacker(ModuleTestBase):
    targets = ["http://127.0.0.1:8888/"]
    modules_overrides = ["jspacker", "badsecrets", "http"]

    weak_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtdGVzdCIsInJvbGUiOiJhZG1pbiJ9.14R5znmeEgKJD6asSoiXbK7wc44nGGlPJcc5lsyYq00"

    async def setup_after_prep(self, module_test):
        packed = pack(f'var platformToken = "{self.weak_jwt}"; console.log(platformToken);')
        assert self.weak_jwt not in packed, "packed fixture must hide the contiguous JWT"
        response_data = f"<html><body><h1>Test</h1><script>{packed}</script></body></html>"
        module_test.set_expect_requests(respond_args={"response_data": response_data})

    def check(self, module_test, events):
        assert any(
            e.type == "HTTP_RESPONSE" and "js-unpacked" in e.tags and self.weak_jwt in e.body for e in events
        ), "jspacker did not emit an unpacked HTTP_RESPONSE containing the revealed JWT"

        assert any(
            e.type == "FINDING"
            and str(e.module) == "badsecrets"
            and "Known Secret Found." in e.data["description"]
            and "1234" in e.data["description"]
            and self.weak_jwt in e.data["description"]
            for e in events
        ), "badsecrets did not crack the JWT revealed by jspacker"
