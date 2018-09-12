
class SignatureParseException(Exception):
    pass

class FixedByte():
    def __init__(self, value):
        self.value = value.upper()

    def __repr__(self):
        return self.value

class FixedString():
    def __init__(self, fixed_bytes):
        self.fixed_bytes = fixed_bytes

    def clone_prepend(self, byte):
        return self.__class__([byte] + self.fixed_bytes)

    def __repr__(self):
        return "%s(%s)" %  (self.__class__.__name__, " ".join(x.__repr__() for x in self.fixed_bytes))

class FixedStringLenTwo(FixedString):
    pass

class ShortSkip():
    def __init__(self, min, max):
        self.min = min
        self.max = max

class Skip():
    INFINITY = -1
    def __init__(self, min, max):
        self.min = min
        self.max = max

    def __repr__(self):
        if self.max == Skip.INFINITY:
            return "Skip(%d, infinity)" % self.min
        else:
            return "Skip(%d, %d)" % (self.min, self.max)

class Choice():
    def __init__(self, choice):
        self.choice = choice

    def __repr__(self):
        return "Choice(%s)" % (", ".join(x.__repr__() for x in self.choice))

class Not():
    def __init__(self, value):
        self.value = value

class HighNibble():
    def __init__(self, nibble):
        self.nibble = nibble

    def __repr__(self):
        return "%s?" % self.nibble

class LowNibble():
    def __init__(self, nibble):
        self.nibble = nibble

    def __repr__(self):
        return "?%s" % self.nibble



class CondSubsignature(object):
    def __init__(self, num):
        self.number = num

    def __repr__(self):
        return "Sig(%d)" % self.number

class CondLogical(object):
    COND_AND = "&"
    COND_OR = "|"

    def __init__(self, type, a, b):
        self.type = type
        self.a = a
        self.b = b

    def __repr__(self):
        return "(%s)%s(%s)" % (repr(self.a), self.type, repr(self.b))
class CondAnd(CondLogical):
    def __init__(self, a, b):
        super(CondAnd, self).__init__(CondLogical.COND_AND, a, b)

class CondOr(CondLogical):
    def __init__(self, a, b):
        super(CondOr, self).__init__(CondLogical.COND_OR, a, b)

class CondMatch(object):
    MATCH_EQUAL = "="
    MATCH_MORE  = ">"
    MATCH_LESS  = "<"
    
    def __init__(self, type, condition, count, min_signatures = 1):
        self.type = type
        self.condition = condition
        self.count = count
        self.min_signatures = min_signatures

    def __repr__(self):
        if self.min_signatures == 0:
            return "(%s)%s%d" % (repr(self.condition), self.type, self.count)
        else:
            return "(%s)%s%d,%d" % (repr(self.condition), self.type, self.count, self.min_signatures)

class CondMatchExact(CondMatch):
    def __init__(self, condition, count, min_signatures = 0):
        super(CondMatchExact, self).__init__(CondMatch.MATCH_EQUAL, condition, count, min_signatures)

class CondMatchMore(CondMatch):
    def __init__(self, condition, count, min_signatures = 0):
        super(CondMatchMore, self).__init__(CondMatch.MATCH_MORE, condition, count, min_signatures)

class CondMatchLess(CondMatch):
    def __init__(self, condition, count, min_signatures = 0):
        super(CondMatchLess, self).__init__(CondMatch.MATCH_LESS, condition, count, min_signatures)
