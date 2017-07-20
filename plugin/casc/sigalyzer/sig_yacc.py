from casc.sigalyzer.sig_lex import tokens, lexer
import ply.yacc as yacc
from casc.sigalyzer.common import SignatureParseException, \
   FixedByte, FixedString, FixedStringLenTwo, Skip, \
   Choice, ShortSkip, Not, HighNibble, LowNibble 

def p_signature(p):
    '''signature : exprwithfixed
                 | signature skip signature
                 | signature ANY signature'''
    if len(p) == 2:
        p[0] = p[1]
    elif p[2] == '*':
        p[0] = p[1] + [Skip(0, Skip.INFINITY)] + p[3]
    else:
        p[0] = p[1] + [p[2]] + p[3]

def p_skip(p):
    '''skip : LBRACE number MINUS number RBRACE
            | LBRACE MINUS number RBRACE
            | LBRACE number MINUS RBRACE'''
    if len(p) == 6:
        p[0] = Skip(int(p[2]), int(p[4]))
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

def p_exprwithfixed(p):
    '''exprwithfixed : fixedexpr
                     | repexpr fixedexpr
                     | fixedexpr repexpr'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + p[2]


def p_fixedexpr(p):
    '''fixedexpr : fixedstringtwo
                 | anchoredshortskip'''
    if isinstance(p[1], FixedStringLenTwo):
        p[0] = [p[1]]
    else:
        p[0] = p[1]

def p_anchoredshortskip(p):
    '''anchoredshortskip : fixedbyte fixedbyte LBRACKET number MINUS number RBRACKET fixedbyte
                         | fixedbyte LBRACKET number MINUS number RBRACKET fixedbyte fixedbyte'''
    if p[2] == "[":
        p[0] = [FixedString([p[1]]), ShortSkip(int(p[3]), int(p[5])), FixedStringLenTwo([p[7], p[8]])]
    else:
        p[0] = [FixedStringLenTwo([p[1], p[2]]), ShortSkip(int(p[4]), int(p[6])), FixedString([p[8]])]

def p_repexpr(p):
    '''repexpr : expr 
               | expr repexpr'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + p[2]

def p_expr(p):
    '''expr : choice
            | negatedchoice
            | highnibble
            | lownibble
            | skipbytes
            | fixedstring'''
    p[0] = [p[1]]

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
    '''choiceelem : choiceexpr
                  | choiceexpr choiceelem'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + p[2]

def p_choiceexpr(p):
    '''choiceexpr : fixedstring
                  | expr'''
    if isinstance(p[1], FixedByte) or isinstance(p[1], FixedString):
        p[0] = [p[1]]
    else:
        p[0] = p[1]

def p_negatedchoice(p):
    '''negatedchoice : NOT choice'''
    p[0] = Not(p[3])
    
def p_hexchar(p):
    '''hexchar : DIGIT
               | HEXALPHA'''
    p[0] = p[1]

def p_fixedbyte(p):
    '''fixedbyte : hexchar hexchar'''
    p[0] = FixedByte("%s%s" % (p[1], p[2]))

def p_fixedstringtwo(p):
    '''fixedstringtwo : fixedbyte fixedbyte
                      | fixedstringtwo fixedbyte'''
    if isinstance(p[1], FixedByte):
        p[0] = FixedStringLenTwo([p[1], p[2]])
    else:
        p[0] = p[1].clone_append(p[2])

def p_fixedstring(p):
    '''fixedstring : fixedbyte
                   | fixedstring fixedbyte'''
    if len(p) == 2:
        p[0] = FixedString([p[1]])
    else:
        p[0] = p[1].clone_append(p[2])

def p_highnibble(p):
    '''highnibble : hexchar NIBBLEMASK'''
    p[0] = HighNibble(p[1])
    
def p_lownibble(p):
    '''lownibble : NIBBLEMASK hexchar'''
    p[0] = LowNibble(p[2])

def p_skipbytes(p):
    '''skipbytes : skipbyte
                 | skipbyte skipbytes'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = Skip(p[2].min + 1, p[2].max + 1)
    
def p_skipbyte(p):
    '''skipbyte : NIBBLEMASK NIBBLEMASK'''    
    p[0] = Skip(1, 1)

start = 'signature'


def p_error(p):
    if p:
        raise SignatureParseException("Syntax error in input at input token '%s' at position %d" % (p[1], p.lexpos(1)))
    else:
        raise SignatureParseException("Unexpected end of file")

parser = yacc.yacc(tabmodule = "sigtab", write_tables = False)

def parse_pattern(signature):
    return parser.parse(signature, lexer = lexer)
#result = parser.parse("4f5c*2345{-12}ccdd((aa|f?)|bb|cc)????00")
#print(result)

