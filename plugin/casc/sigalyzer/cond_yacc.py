from __future__ import absolute_import

import ply.yacc as yacc
from .cond_lex import tokens, lexer
from .common import SignatureParseException, \
    CondSubsignature, CondAnd, CondOr, CondMatchExact, \
    CondMatchMore, CondMatchLess

precedence = (
    ("right", "NUMBER"),
    ("left", "OR"),
    ("left", "AND"),
    ("nonassoc", "LESS", "GREATER", "EQUAL"),
    ("left", "COMMA"),
    ("left", "LPAREN", "RPAREN"),
)


def p_expr(p):
    '''expr : paren
            | and
            | or
            | matchexact
            | matchmore
            | matchless
            | subsig'''
    p[0] = p[1]

def p_subgroup(p):
    '''subgroup : subsig
                | paren'''
    p[0] = p[1]
    
def p_subsig(p):
    '''subsig : NUMBER'''
    p[0] = CondSubsignature(int(p[1]))

def p_paren(p):
    '''paren : LPAREN expr RPAREN'''
    p[0] = p[2]

def p_and(p):
    '''and : expr AND expr'''
    p[0] = CondAnd(p[1], p[3])

def p_or(p):
    '''or : expr OR expr'''
    p[0] = CondOr(p[1], p[3])

def p_matchextact(p):
    '''matchexact : subgroup EQUAL NUMBER
                  | subgroup EQUAL NUMBER COMMA NUMBER'''
    if len(p) == 6:
        min_signatures = int(p[5])
    else:
        min_signatures = 0
    p[0] = CondMatchExact(p[1], int(p[3]), min_signatures)

def p_matchmore(p):
    '''matchmore : subgroup GREATER NUMBER
                 | subgroup GREATER NUMBER COMMA NUMBER'''
    if len(p) == 6:
        min_signatures = int(p[5])
    else:
        min_signatures = 0
    p[0] = CondMatchMore(p[1], int(p[3]), min_signatures)

def p_matchless(p):
    '''matchless : subgroup LESS NUMBER
                 | subgroup LESS NUMBER COMMA NUMBER'''
    if len(p) == 6:
        min_signatures = int(p[5])
    else:
        min_signatures = 0
    p[0] = CondMatchLess(p[1], int(p[3]), min_signatures)

def p_error(p):
    if p:
        raise SignatureParseException("Syntax error in logical block at input token '%s' at position %d" % (p.value, p.lexpos))
    else:
        raise SignatureParseException("Unexpected end of file in logical block")

parser = yacc.yacc(tabmodule = "condtab", write_tables = False)

def parse_condition(logical):
    return parser.parse(logical, lexer = lexer)
