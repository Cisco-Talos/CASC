import re
import logging
from casc.sigalyzer.sig_yacc import parse_pattern
from casc.sigalyzer.cond_yacc import parse_condition
from casc.sigalyzer.common import SignatureParseException

log = logging.getLogger("sigalyzer.clamav")

class AnyOffset():
    def __init__(self):
        pass

    def __str__(self):
        return "*"

class AbsoluteOffset():
    def __init__(self, start, end = None):
        self.start = start
        self.end = end

    def __str__(self):
        return "%d%s" % (self.start, ",%d" % self.end if self.end is not None else "")

class EPRelativeOffset():
    def __init__(self, offset, shift = None):
        self.offset = offset
        self.shift = shift

    def __str__(self):
        return "EP%s%d%s" % ("+" if self.offset >= 0 else "-", abs(self.offset), ",%d" % self.shift if self.shift is not None else "")

class EOFRelativeOffset():
    def __init__(self, offset, shift = None):
        self.offset = offset
        self.shift = shift

    def __str__(self):
        return "EOF-%d%s" % (self.offset, ",%d" % self.shift if self.shift is not None else "")

class InSectionOffset():
    def __init__(self, section):
        self.section = section

    def __str__(self):
        return "SE%d" % self.section

class SectionRelativeOffset():
    def __init__(self, section, offset, shift = None):
        self.section = section
        self.offset = offset
        self.shift = shift

    def __str__(self):
        return "S%d+%d%s" % (self.section, self.offset, ",%d" % self.shift if self.shift is not None else "")


def parse_offset(offset):
    RE_OFFSET_ANY = re.compile("\*")
    RE_OFFSET_ABSOLUTE = re.compile("([0-9]+)(,([0-9]+))?")
    RE_OFFSET_EP_RELATIVE = re.compile("EP((-|\+)[0-9]+)(,([0-9]+))?")
    RE_OFFSET_EOF_RELATIVE = re.compile("EOF-([0-9]+)(,([0-9]+))?")
    RE_SECTION_RELATIVE = re.compile("S([0-9]+)+([0-9]+)(,([0-9]+))?")
    RE_IN_SECTION = re.compile("SE([0-9]+)")

    if RE_OFFSET_ANY.match(offset):
        return AnyOffset()
    elif RE_OFFSET_ABSOLUTE.match(offset):
        match = RE_OFFSET_ABSOLUTE.match(offset)
        return AbsoluteOffset(int(match.group(1)), int(match.group(3)) if match.group(3) else None)
    elif RE_OFFSET_EP_RELATIVE.match(offset):
        match = RE_OFFSET_EP_RELATIVE.match(offset)
        return EPRelativeOffset(int(match.group(1)), int(match.group(3)) if match.group(3) else None)
    elif RE_OFFSET_EOF_RELATIVE.match(offset):
        match = RE_OFFSET_EOF_RELATIVE.match(offset)
        return EOFRelativeOffset(int(match.group(1)), int(match.group(3)) if match.group(3) else None)
    elif RE_SECTION_RELATIVE.match(offset):
        match = RE_SECTION_RELATIVE.match(offset)
        return SectionRelativeOffset(int(match.group(1)), int(match.group(2)), int(match.group(4)) if match.group(4) else None)
    elif RE_IN_SECTION.match(offset):
        return InSectionOffset(int(RE_IN_SECTION.match(offset).group(1)))
    else:
        log.error("Unknown signature offset: %s", offset)
        raise SignatureParseException("Unknown signature offset format")

def parse_modifiers(modifiers):
    return None

class SubSignature():
    @classmethod
    def parse(clazz, offset, pattern, modifiers = ""):
        return clazz(parse_offset(offset), parse_pattern(pattern), parse_modifiers(modifiers), pattern)

    def __init__(self, offset, signature, modifiers, clamav_signature = None):
        self.offset = offset
        self.signature = signature
        self.modifiers = modifiers
        self.clamav_signature = clamav_signature

class NdbSignature():
    @classmethod
    def parse(clazz, sig):
        elements = sig.split(":")
        if len(elements) < 4 or len(elements) > 6:
            raise SignatureParseException("Signature '%s' does not seem to be an NDB signature" % sig)
        try:
            return clazz(
                    elements[0],
                    int(elements[1]),
                    SubSignature.parse(elements[2], elements[3]),
                    int(elements[4]) if len(elements) >= 5 else 1,
                    int(elements[5]) if len(elements) >= 6 else 255)
        except ValueError:
            raise SignatureParseException("Error converting values; Signature '%s' does not seem to be an NDB signature" % sig)

    def __init__(self, name, target_type, signature, min_flevel = 1, max_flevel = 255):
        self.name = name
        self.target_type = target_type
        self.signature = signature
        self.min_flevel = min_flevel
        self.max_flevel = max_flevel

class LdbSignature():
    @classmethod
    def parse(clazz, sig):
        elements = sig.split(";")
        if len(elements) < 4:
            raise SignatureParseException("Signature is not an LDB signature")
        name = elements[0]
        tbd = clazz._parse_target_description_block(elements[1])
        condition = parse_condition(elements[2])
        subsignatures = []
        for (i, subsig) in enumerate(elements[3:]):
            elems = subsig.split(":")
            if len(elems) == 1:
                subsignatures.append(SubSignature.parse("*", elems[0]))
            elif len(elems) == 2:
                subsignatures.append(SubSignature.parse(elems[0], elems[1]))
            elif len(elems) == 3 and elems[1] == "":
                subsignatures.append(SubSignature.parse("*", elems[0], elems[2]))
            elif len(elemes) == 4 and elems[2] == "":
                subsignatures.append(SubSignature.parse(elems[0], elems[1], elems[3]))
            else:
                raise SignatureParseException("Cannot parse subsignature %d of LDB signature" % i)
        return clazz(name, condition, subsignatures, **tbd)


    @classmethod
    def _parse_target_description_block(clazz, tdb):
        elements = tdb.split(",")
        parsed = {}
        for element in elements:
            if not element:
                continue
            k, v = element.split(":")
            if k == "Target":
                parsed["target_type"] = int(v)
            elif k == "Engine":
                min, max = v.split("-")
                parsed["engine"] = (int(min), int(max))
            else:
                raise NotImplementedError("Target description block entry %s not implemented" % k)

        if "target_type" not in parsed:
            parsed["target_type"] = 0
        if "engine" not in parsed:
            parsed["engine"] = (1, 255)

        return parsed

    def __init__(self, name, condition, subsignatures, target_type = 0, engine = (1, 255)):
        self.name = name
        self.condition = condition
        self.subsignatures = subsignatures
        self.target_type = target_type
        self.engine = engine


def parse_signature(signature):
    if signature.count(";") >= 3:
        return LdbSignature.parse(signature)
    else:
        return NdbSignature.parse(signature)
