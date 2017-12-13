from casc.sigalyzer.sig_lex import tokens, lexer
import ply.yacc as yacc
import logging
from casc.sigalyzer.common import SignatureParseException, \
   FixedByte, FixedString, FixedStringLenTwo, Skip, \
   Choice, ShortSkip, Not, HighNibble, LowNibble 

def p_signature(p):
    '''signature : expr
                 | expr signature'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        if isinstance(p[1], Skip) and isinstance(p[2][0], Skip):
            if p[1].max == Skip.INFINITY or p[2][0].max == Skip.INFINITY:
                max = Skip.INFINITY
            else:
                max = p[1],max + p[2][0].max
            p[0] = [Skip(p[1].min + p[2][0].min, max)] + p[2][1:]
        elif isinstance(p[1], FixedByte) and isinstance(p[2][0], FixedByte):
            p[0] = [FixedString([p[1], p[2][0]])] + p[2][1:]
        elif isinstance(p[1], FixedByte) and isinstance(p[2][0], FixedString):
            p[0] = [p[2][0].clone_prepend(p[1])] + p[2][1:]
        else:
            p[0] = [p[1]] + p[2]

def p_expr(p):
    '''expr : fixedbyte_highnibble
            | lownibble_skipbyte
            | skip
            | any
            | shortskip
            | choice
            | negatedchoice'''
    p[0] = p[1]

def p_any(p):
    '''any : ANY'''
    p[0] = Skip(0, Skip.INFINITY)

def p_hexchar(p):
    '''hexchar : DIGIT
               | HEXALPHA'''
    p[0] = p[1]

def p_fixedbyte_highnibble(p):
    '''fixedbyte_highnibble : fixedbyte
                            | highnibble'''
    p[0] = p[1]

def p_fixedbyte(p):
    '''fixedbyte : hexchar hexchar'''
    p[0] = FixedByte("%s%s" % (p[1], p[2]))

def p_skip(p):
    '''skip : LBRACE number MINUS number RBRACE
            | LBRACE MINUS number RBRACE
            | LBRACE number MINUS RBRACE
            | LBRACE number RBRACE'''
    if len(p) == 6:
        p[0] = Skip(int(p[2]), int(p[4]))
    elif len(p) == 4:
        p[0] = Skip(int(p[2]), int(p[2]))
    elif p[2] == '-':
        p[0] = Skip(0, int(p[3]))
    else:
        p[0] = Skip(int(p[2]), Skip.INFINITY)
         
def p_number(p):
    '''number : DIGIT
              | number DIGIT'''
    if len(p) == 2:
        p[0] = int(p[1])
    else:
        p[0] = p[1] * 10 + int(p[2])

def p_shortskip(p):
    '''shortskip : LBRACKET number MINUS number RBRACKET'''
    return ShortSkip(int(p[2]), int(p[4]))

def p_choice(p):
    '''choice : LPAREN choiceelems RPAREN'''
    p[0] = Choice(p[2])

def p_choiceelems(p):
    '''choiceelems : choiceelem
                   | choiceelem ALTERNATIVE choiceelems'''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[3]

def p_choiceelem(p):
    '''choiceelem : expr
                  | expr choiceelem'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + p[2]

def p_negatedchoice(p):
    '''negatedchoice : NOT choice'''
    p[0] = Not(p[3])
    
def p_highnibble(p):
    '''highnibble : hexchar NIBBLEMASK'''
    p[0] = HighNibble(p[1])

def p_lownibble_skipbyte(p):
    '''lownibble_skipbyte : lownibble
                          | skipbyte'''
    p[0] = p[1]
    
def p_lownibble(p):
    '''lownibble : NIBBLEMASK hexchar'''
    p[0] = LowNibble(p[2])

def p_skipbyte(p):
    '''skipbyte : NIBBLEMASK NIBBLEMASK'''    
    p[0] = Skip(1, 1)

start = 'signature'


def p_error(p):
    if p:
        raise SignatureParseException("Syntax error in input at input token '%s' at position %d" % (p.value, p.lexpos))
    else:
        raise SignatureParseException("Unexpected end of file")

parser = yacc.yacc(tabmodule = "sigtab", write_tables = False)

def parse_pattern(signature):
    return parser.parse(signature, lexer = lexer, debug = logging.getLogger())
#result = parser.parse("4f5c*2345{-12}ccdd((aa|f?)|bb|cc)????00")
#print(result)

