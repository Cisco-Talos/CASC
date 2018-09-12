from __future__ import absolute_import

import ply.lex as lex
from .common import SignatureParseException

tokens = (
    'NUMBER',
    'LPAREN',
    'RPAREN',
    'OR',
    'AND',
    'EQUAL',
    'GREATER',
    'LESS',
    'COMMA',
)

t_NUMBER      = r'[0-9]+'
t_LPAREN      = r'\('
t_RPAREN      = r'\)'
t_OR          = r'\|'
t_AND         = r'&'
t_EQUAL       = r'='
t_GREATER     = r'>'
t_LESS        = r'<'
t_COMMA       = r','

def t_error(t):
    raise SignatureParseException("Illegal character '%s' at position %d in logical block" % (t.value[0], t.lexpos)) 

lexer = lex.lex(lextab = "condtab")
