from __future__ import absolute_import

import ply.lex as lex
from .common import SignatureParseException

tokens = (
    'DIGIT',
    'HEXALPHA',
    'MINUS',
    'ANY',
    'LPAREN',
    'RPAREN',
    'LBRACE',
    'RBRACE',
    'LBRACKET',
    'RBRACKET',
    'NOT',
    'NIBBLEMASK',
    'ALTERNATIVE',
)

t_DIGIT       = r'[0-9]'
t_HEXALPHA    = r'[A-Fa-f]'
t_MINUS       = r'-'
t_ANY         = r'\*'
t_LPAREN      = r'\('
t_RPAREN      = r'\)'
t_LBRACE      = r'\{'
t_RBRACE      = r'\}'
t_LBRACKET    = r'\['
t_RBRACKET    = r'\]'
t_NOT         = r'!'
t_NIBBLEMASK  = r'\?'
t_ALTERNATIVE = r'\|'

def t_error(t):
    raise SignatureParseException("Illegal character '%s' at position %d" % (t.value[0], t.lexpos)) 

lexer = lex.lex(lextab = "sigtab")

#lexer.input("cafebabe?a21212?[0-23]{-}*!(45|46)")

#for token in lexer:
#    print(token) 
