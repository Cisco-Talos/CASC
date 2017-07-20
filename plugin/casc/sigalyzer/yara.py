from casc.sigalyzer.common import SignatureParseException, \
   FixedByte, FixedString, FixedStringLenTwo, Skip, \
   Choice, ShortSkip, Not, HighNibble, LowNibble 
from casc.sigalyzer.common import CondSubsignature, \
    CondAnd, CondOr, CondMatchExact, CondMatchMore, \
    CondMatchLess
from casc.sigalyzer.clamav import NdbSignature, LdbSignature, parse_signature
from casc.sigalyzer.clamav import AbsoluteOffset, EPRelativeOffset, \
    InSectionOffset, SectionRelativeOffset, EOFRelativeOffset, \
    AnyOffset
import re


def _to_yara_pattern(sig):
    if isinstance(sig, FixedString):
        return " ".join(x.value for x in sig.fixed_bytes)
    elif isinstance(sig, Skip):
        min = "" if sig.min == 0 else "%d" % sig.min
        max = "" if sig.max == Skip.INFINITY else "%d" % sig.max
        return "[%s-%s]" % (min, max)
    elif isinstance(sig, ShortSkip):
        return "[%d-%d]" % (sig.min, sig.max)
    elif isinstance(sig, HighNibble):
        return "%s?" % sig.nibble
    elif isinstance(sig, LowNibble):
        return "?%s" % sig.nibble
    elif isinstance(sig, Not):
        raise NotImplementedError("Negation is not yet implemented for yara signature conversion")
    elif isinstance(sig, Choice):
        return "(%s)" % "|".join(_to_yara_pattern(x) for x in sig.choice)
    elif isinstance(sig, list):
        return " ".join(_to_yara_pattern(x) for x in sig)

def _to_yara_condition(cond):
    if isinstance(cond, CondSubsignature):
        return "$subsig_%02d" % cond.number
    elif isinstance(cond, CondAnd):
        return "(%s) and (%s)" % (_to_yara_condition(cond.a), _to_yara_condition(cond.b))
    elif isinstance(cond, CondOr):
        return "(%s) or (%s)" % (_to_yara_condition(cond.a), _to_yara_condition(cond.b))
    elif isinstance(cond, CondMatchExact):
        if not isinstance(cond.condition, CondSubsignature):
            raise NotImplementedError("Support for logical groups in match expression is not yet implemented")
        return "#subsig_%02d == %d" % (cond.condition.number, cond.count)
    elif isinstance(cond, CondMatchLess):
        if not isinstance(cond.condition, CondSubsignature):
            raise NotImplementedError("Support for logical groups in match expression is not yet implemented")
        return "#subsig_%02d < %d" % (cond.condition.number, cond.count)
    elif isinstance(cond, CondMatchMore):
        if not isinstance(cond.condition, CondSubsignature):
            raise NotImplementedError("Support for logical groups in match expression is not yet implemented")
        return "#subsig_%02d > %d" % (cond.condition.number, cond.count)


def _target_type_condition(target_type):
    if target_type == 0:
        return "true"
    elif target_type == 1:
        return "uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550"
    else:
        raise NotImplementedError("Target type %d is not yet implemented" % target_type)

def _offset_condition(offset, rulename):
    if isinstance(offset, AnyOffset):
        return "true"
    elif isinstance(offset, AbsoluteOffset):
        if offset.end is None:
            return "$%s at %d" % (rulename, offset.start)
        else:
            return "$%s in (%d..%d+%d)" % (rulename, offset.start, offset.start, offset.end)
    elif isinstance(offset, EPRelativeOffset):
        offs = abs(offset.offset)
        sign = "+" if offset.offset >= 0 else "-"
        if offset.shift is None:
            return "$%s at (pe.entry_point %s %d)" % ( rulename, sign, offs)
        else:
            return "$%s in (pe.entry_point%s%d..pe.entry_point%s%d+%d)" % \
                (rulename, sign, offs, sign, offs, offset.shift)
    elif isinstance(offset, EOFRelativeOffset):
        if offset.shift is None:
            return "$%s at (filesize-%d)" % (rulename, offset.offset)
        else:
            return "$%s in (filesize-%d..filesize-%d+%d)" % (rulename, offset.offset, offset.offset, offset.shift)
    elif isinstance(offset, InSectionOffset):
        return "$%s in (pe.sections[%d].raw_data_offset..pe.sections[%d].raw_data_offset+pe.sections[%d].raw_data_size)" % \
            (offset.section, offset.section, offset.section)
    elif isinstance(offset, SectionRelativeOffset):
        if offset.shift is None:
            return "$%s at (pe.sections[%d].raw_data_offset+%d)" % (offset.section, offset.offset)
        else:
            return "$%s in (pe.sections[%d].raw_data_offset+%d..pe.sections[%d].raw_data_offset+%d+%d)" % \
                (offset.section, offset.offset, offset.section, offset.offset, offset.shift)
    else:
        raise NotImplementedError("Offset type %s is not implemented" % offset.__class__.__name__)

def convert_to_yara(signature, offset_converter = _offset_condition):
    name = re.sub(r'[^0-9A-Za-z_]', '_', signature.name)
    if name[0] in '0123456789':
        name = "_" + name
    target_type_condition = _target_type_condition(signature.target_type)
    if isinstance(signature, NdbSignature):
        offset_condition = offset_converter(signature.signature.offset, "pattern")
        return """import "pe"

rule %s {
    strings:
        $pattern = { %s }
    condition:
        (%s) and (%s) and $pattern
}""" % (name, _to_yara_pattern(signature.signature.signature), target_type_condition, offset_condition)
    elif isinstance(signature, LdbSignature):
        offset_conditions = []
        patterns = []
        for i, subsig in enumerate(signature.subsignatures):
            subsig_name = "subsig_%02d" % i
            offset_conditions.append(offset_converter(subsig.offset, subsig_name))
            patterns.append((subsig_name, _to_yara_pattern(subsig.signature)))
        return """import "pe"

rule %s {
    strings:
        %s
    condition:
        (%s) and (%s) and (%s)
}""" % (name, "\n        ".join("$%s = { %s }" % ptrn for ptrn in patterns), target_type_condition, " and ".join("(%s)" % x for x in offset_conditions), _to_yara_condition(signature.condition))
