#-------------------------------------------------------------------------------
#   
#   Copyright (C) 2015 Cisco Talos Security Intelligence and Research Group
#   
#   IDA Pro Plug-in: ClamAV Signature Creator (CASC)
#   Author: Angel M. Villegas
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#   
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#   
#   Last revision: April 2015
#   This IDA Pro plug-in will aid in creating ClamAV ndb and ldb signatures
#   from data within the IDB the user selects.
#   
#   Installation
#   ------------
#   Drag and drop into IDA Pro's plugin folder for IDA Pro 6.6 and higher.
#   To gain all the features of this plug-in, using IDA Pro 6.7 or higher.
#   Older versions of IDA Pro may require other Python packages (i.e. PySide, 
#   Qt, etc.)
#
#-------------------------------------------------------------------------------


#   Python Modules from IDA Pro 6.6 and higher
from idaapi import *
from idc import *

from PySide import QtGui, QtCore
from PySide.QtCore import Qt

#   Python Modules
import collections
import pickle
import re
import csv
from urllib import quote_plus

#   Constants
#-------------------------------------------------------------------------------
OT_NONE = 0
OT_REGISTER = 1
OT_MEMORY_REFERENCE = 2
OT_BASE_INDEX = 3
OT_BASE_INDEX_DIS = 4
OT_IMMEDIATE = 5

OT = {  0 : 'None', 1 : 'General Register', 2 : 'Memory Reference', 
        3 : 'Base + Index', 4 : 'Base + Index + Displacement', 5 : 'Immediate' }

#   Global Variables
#-------------------------------------------------------------------------------
b_asm_sig_handler_loaded = True
clamav_sig_creator_plugin = None
add_sig_handler_in_menu = False
valid_address_ranges = []

CLAMAV_ICON = None


#   Misc Helper Functions
#-------------------------------------------------------------------------------
def get_file_type():
    #   ClamAV Types: {1 : 'PE', 6 : 'ELF', 9 : 'Mach-O', 0 : 'Any'}
    file_type = get_file_type_name()
    if None == file_type:
        return 0

    file_type = file_type.lower()
    if 'mach-o' in file_type:
        return 9
    elif 'elf' in file_type:
        return 6
    elif ('pe' in file_type) or ('.net' in file_type):
        return 1

    return 0;

def is_32bit():
    return '86' in get_file_type_name()

def get_clamav_icon(return_hex=False, return_pixmap=False):
    clamav_icon = ( '89504E470D0A1A0A0000000D494844520000001A0000001A08060000'
                    '00A94A4CCE000000097048597300000B1300000B1301009A9C180000'
                    '001974455874536F6674776172650041646F626520496D6167655265'
                    '61647971C9653C000004A54944415478DABC965F4CDB5514C7BFF7D7'
                    '5FFFD0C2DA04D8803A680B5306E34F7046972CA1D944F73081FD8926'
                    'EADC740F2688CB78501F8C913D9810E616E28359E603F3498D89AB31'
                    'B06571A6304748468031D9A285B4FC29B004C8DA425B28FDFD3CF757'
                    '685A2819F3CF9ADCFE7EBF7BEF399F7BCE3DE7DCCB6459C653F971D0'
                    'B0B9C4C29FFF754BD42BACF2DAFE273BE27A45FE770B912C3C535A5F'
                    '3239EC583FF34A5189A59289F56AC04E9FA675C34E6A8E52D7D0E07A'
                    'B9FBA4AF13CBB925ABDF8C9BF58ED97AB591A51D4807AB269822D45C'
                    '586C7A9E896D36269CDCC2CABBFC909BF7B9EE39572195D390BA2FCA'
                    'C1810EEF58751C5466DED970089A8BEF32DD0CF5557EA78D56EE652A'
                    '471153199FC44F3EC8E74C2189BB6BB0450EE60E60A5E99E77E2EB38'
                    'C86C369BC835D3ED6C9B2E1B42E8B22A9C661544BC226AB70CE9892E'
                    'E3EE4A042724ED7210B2E66DD9CFBBAD5EAFD71307F11FC11C855055'
                    '5F6219B17D6014913AD596412C1C2581D87B831C587421DA4710FBDA'
                    'B8901821A3889A3EC32216B8041792B69863526C3E97FB9CE4096230'
                    '0BE2A5C42971D03E8D1EF9E4AE5E3982F3E0C6D390C0B606A2797C3E'
                    '97EB21F92A951AAF6BF4875282D218CEAE39AA50A4A857B127CB189A'
                    '5FAED628AFB3B204DADDFA942011CCCE27EC22AB4EA8F5FF283B8F8A'
                    '3A940B6A05448A8D676CCF26EFD1416BA185D66FDC4F5156AF4E43E4'
                    '5F94828FB4E9784F6D4034F6990CA27DB448F4BF5325225310683B93'
                    '83A02FBC883F97C31B94FE160C20204593FAB2988062D2C3171B5DEF'
                    '3A89DA0AB5250AF54562388B0A70EDCD23E83368D13A3783D3D363F8'
                    '39F06803BCE9E18432F6905CF54B55296E57ED818FEBA08586A82D27'
                    'CC576A1D413C4B040892FFE649E8F8F916ECDABD1BBD3535386DB7A3'
                    '26DD888F337392407B75067C9A95872F66A7D079B806AD17BE442810'
                    'C0B5DAE3F07BBD08127029C1338A45BFBB473D61C83E0A6A78E4288C'
                    '9999CAE05F2E17F2F3F3D13E3480FEDA57B19070760DE56463FF5717'
                    'F0616323FA87EE2A7D1ABD1E93C545A0BAA7E45448568A6E72D491A9'
                    '4E3EC87DEBF7FB110E8731363686BADA5A6C379BF1566B0BF21CDF23'
                    '92978BC94FCEE20DE70D1C3C7614B57575E8EEEE56744CCFCCC0B7B0'
                    'A0B86F814ADF8F6E572A10DAF88A1963982080DBE3C10C09728BE2B9'
                    '9695A928297DF940BCCF5250A0CC191F1FC7FCDC1C82BD77F088161C'
                    '906547CA3CBAED1EE51675F949D195F73FC0FCFC3C8A699F8C2613FE'
                    '181E56DAF59FAE223035859B97BFC1FD070F94C58497965051518100'
                    'EDCF0F0D679440A02AEE0BD0B191540B13EF0C2F5A6D954630A71182'
                    '91E778765929B697976147CE0E4CDDEA41FA9D7E18287C79CD98DDF3'
                    '1C6CAF1DC636B2F266470742BF3A2191377C1C24CB4D1DEE91B64D41'
                    '4ACDB3169ECA00DA33485D3A091AE899468D1F186AFA5E2B534A4AC8'
                    'B110E6A11CA427773D59F26DA77BE4D486EA9EEA16F492D566278043'
                    '0F66E4101D99A0A5A7B8EA6B96907B1182F0540EC90AECDC0DF74873'
                    'CA6364B3EBD60B169B49C7589B0E38A921D59A583D8C6FAAA4647E2C'
                    '4AC9AA2ECA996627EDF3A6E7D5E3EE7504B46818AB276BECE4361381'
                    '2CD4ED916325C6495639280F071F7B303EAD0BE4DF020C0026BB3556'
                    '2D86F1AC0000000049454E44AE426082')

    if return_hex:
        return clamav_icon

    image = QtGui.QImage()
    image.loadFromData(QtCore.QByteArray.fromHex(clamav_icon))

    pixmap = QtGui.QPixmap()
    pixmap.convertFromImage(image)
    if return_pixmap:
        return pixmap

    return QtGui.QIcon(pixmap)

def verify_clamav_sig(sig):
    sig_format = (  '^(([\da-fA-F\?]{2})|(\{(?:\d+|\-\d+|\d+\-|(?:\d+)\-(?:\d+)'
                    ')})|\*|((?:!|)\([\da-fA-F]{2}(?:\|[\da-fA-F]{2})+\))|(\('
                    '(?:B|L)\)))+$')
    pattern = ( '([\da-fA-F\?]{2})|(\{(?:\d+|\-\d+|\d+\-|(?:\d+)\-(?:\d+))})|('
                '\*)|((?:!|)\([\da-fA-F]{2}(?:\|[\da-fA-F]{2})+\))|(\((?:B|L)'
                '\))')
    
    if None == re.match(sig_format, sig):
        return 'Invalid signature, check ClamAV signature documentation'

    matches = map(lambda x: filter(None, x)[0], re.findall(pattern, sig))
    for i in xrange(len(matches)):
        if matches[i].startswith('{'):
            #   Ensure that there are two bytes before and after
            if (i-2 < 0) or (i+2 >= len(matches)):
                return ('Invalid signature, two hex bytes are not before and '
                        'after {*} expression')

            #   Check bytes before and after for valid hex strings
            for j in [i-2, i-1, i+1, i+2]:
                if None == re.match('[\da-fA-F]{2}', matches[j]):
                    return ('Invalid signatrue, hex byte at {0} ({1}) is not '
                            'an actual byte value'.format(j, matches[j]))

        #   Look {n-m} extension
        values = re.match('\{(\d+)\-(\d+)\}', matches[i])
        if None != values:
            if values.group(2) <= values.group(1):
                return 'Invalid signature, m is less than or equal to n'

    return None

def get_block(ea):
    '''
    Given a virtual address, this function will return a block object or None
    '''
    ea_func = get_func(ea)

    #   Ensure ea is in a function
    if ea_func:
        fc = FlowChart(ea_func)

        for block in fc:
            #   Check address selected is in the block's range
            if (block.startEA <= ea) and (ea < block.endEA):
                return block

    return None

def get_existing_segment_ranges():
    return map(lambda x: [x.startEA, x.endEA], map(getseg, Segments()))

def is_in_sample_segments(ea):
    global valid_address_ranges
    
    for segment_range in valid_address_ranges:
        if segment_range[0] <= ea < segment_range[1]:
            return True

    return False

#   Create ClamAV icon
CLAMAV_ICON = get_clamav_icon(True).decode('hex')
CLAMAV_ICON = load_custom_icon(data=CLAMAV_ICON, format='png')

#   Misc Qt components extended/customized
#-------------------------------------------------------------------------------
class OneLineQPlainTextEdit(QtGui.QPlainTextEdit):
    def __init__(self):
        super(OneLineQPlainTextEdit, self).__init__()
        self.setLineWrapMode(QtGui.QPlainTextEdit.LineWrapMode.NoWrap)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        self.setTabChangesFocus(True)

    def keyPressEvent(self, event):
        if event.key() in [Qt.Key_Return, Qt.Key_Enter]:
            event.ignore()
        else:
            super(OneLineQPlainTextEdit, self).keyPressEvent(event)


#   Action Handler Classes - Supported for IDA Pro 6.7 and higher
#-------------------------------------------------------------------------------
try:
    #   Action Handlers, support added with IDA Pro 6.7
    class CASCActionHandler(action_handler_t):
        def __init__(self, fn):
            action_handler_t.__init__(self)
            self.fn = fn

        def activate(self, ctx):
            self.fn(ctx)
            return 1

        def update(self, ctx):
            return AST_ENABLE_ALWAYS

    class CASCHooks(UI_Hooks):
        def __init__(self):
            super(CASCHooks, self).__init__()
            self.handlers_created = False

        def finish_populating_tform_popup(self, form, popup):
            global CLAMAV_ICON, clamav_sig_creator_plugin

            if None == clamav_sig_creator_plugin:
                return 

            if not self.handlers_created:
                self.init_actions()
                self.handlers_created = True

            #   Apply the right action to the popup menu
            tform_type = get_tform_type(form)
            if BWN_DISASMS == tform_type:
                attach_action_to_popup(form, popup, 'clamav:add_sig')

            elif BWN_STRINGS == tform_type:
                attach_action_to_popup(form, popup, 'clamav:add_string')

        def init_actions(self):
            global CLAMAV_ICON, clamav_sig_creator_plugin

            add_sig_handler = CASCActionHandler(clamav_sig_creator_plugin.insert_asm_item) 
            add_sig_action_desc = action_desc_t('clamav:add_sig', 
                                                'Add Assembly to ClamAV Sig Creator...', 
                                                add_sig_handler, 
                                                'Ctrl+`', 
                                                'From current selection or selected basic block', 
                                                CLAMAV_ICON)
            register_action(add_sig_action_desc)

            strings_handler = CASCActionHandler(clamav_sig_creator_plugin.insert_string_item)
            strings_action_desc = action_desc_t('clamav:add_string', 
                                                'Add string to ClamAV Sig Creator', 
                                                strings_handler,
                                                None,
                                                'Add current string as sub signature',
                                                CLAMAV_ICON)
            register_action(strings_action_desc)

    hooks = CASCHooks()
    hooks.hook()

except NameError:
    b_asm_sig_handler_loaded = False


#   Disassembly and Opcodes Classes
#-------------------------------------------------------------------------------
class Assembly(object):
    def __init__(self, start_ea, end_ea):
        self.original_data = []
        self.opcodes = []
        self.mnemonics = []
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.mask_options = {'esp' : False, 'ebp' : False, 'abs_calls' : False, 
                                'global_offsets' : False}
        self.custom = None

        self.starts_in_function = False
        if get_func(start_ea):
            self.starts_in_function = True

        ea = start_ea

        if (BADADDR == start_ea) or (BADADDR == end_ea):
            return

        while ea < end_ea:
            #   Check if it is in a function, if so it can be decoded without 
            #   any issues arising, if not, it should be added as data bytes
            if get_func(ea):
                instr = DecodeInstruction(ea)
                self.original_data.append(instr)

                disassembly = tag_remove(generate_disasm_line(ea, 1))
                if ';' in disassembly:
                    disassembly = disassembly[:disassembly.index(';')].rstrip()

                self.mnemonics.append(disassembly)
                data = ['{0:02x}'.format(Byte(ea + i)) for i in xrange(instr.size)]
                self.opcodes.append(' '.join(data))

                ea += instr.size

            else:
                data_byte = Byte(ea)
                self.original_data.append(data_byte)
                self.mnemonics.append('db {0:02x}h'.format(data_byte))
                self.opcodes.append('{0:02x}'.format(data_byte))
                ea += 1

        self.original_opcodes = self.opcodes
        self.original_mnemonics = self.mnemonics

    def get_opcode_list(self):
        return self.opcodes

    def get_mnemonics_list(self):
        return self.mnemonics

    def set_opcode_list(self, new_opcodes, is_custom=False):
        self.opcodes = new_opcodes

        if is_custom:
            self.custom = new_opcodes

    def opcode_to_signatrue(self):
        return ''.join(self.opcodes).replace(' ', '')

    def mask_opcodes(self, mask_options, is_custom=False):
        self.mask_options.update(mask_options)
        mask_esp = self.mask_options['esp']
        mask_ebp = self.mask_options['ebp']
        mask_abs = self.mask_options['abs_calls']
        mask_global = self.mask_options['global_offsets']

        if is_custom:
            return

        self.custom = None

        reg_to_mask = []
        if self.mask_options['esp']:
            reg_to_mask.append('esp')

        if self.mask_options['ebp']:
            reg_to_mask.append('ebp')

        opcodes = []
        mnemonics = []

        for instr in self.original_data:
            if not isinstance(instr, insn_t):
                #   The data is just a data byte
                opcodes.append('{0:02x}'.format(instr))

            else:
                #   The data is an instruction
                ea = instr.ea
                mnem = GetMnem(ea)

                #   Create original (non-masked) version of the data
                disassembly = tag_remove(generate_disasm_line(ea, 1))
                data = ['{0:02x}'.format(Byte(ea + i)) for i in xrange(instr.size)]
                instr_opcodes = ' '.join(data)

                if ';' in disassembly:
                    disassembly = disassembly[:disassembly.index(';')].rstrip()

                if mask_abs and (mnem == 'call') and (GetOpType(ea, 0) == OT_MEMORY_REFERENCE):
                    mnemonics.append('call    <Absolute Call>')
                    opcodes.append(instr_opcodes[:-11] + '{4}')
                    #   No more masking operations can be done on this instructionn
                    continue

                elif mask_global and ((GetOpType(ea, 0) == OT_IMMEDIATE) or (GetOpType(ea, 1) == OT_IMMEDIATE)):
                    operand_index = 0
                    if GetOpType(ea, 1) == OT_IMMEDIATE:
                        operand_index = 1

                    #   Test if the immediate value can map to a segment that is 
                    #   loaded in the IDB. 
                    value = GetOperandValue(ea, operand_index)
                    if getseg(value):
                        '{0:08x}'.format(value)
                        value = '{0:08x}'.format(value)
                        value = ' '.join([value[-2:], value[4:6], value[2:4], value[:2]])
                        instr_opcodes = instr_opcodes.replace(value, '{4}')

                        if operand_index == 1:
                            disassembly = disassembly[:disassembly.index(',')] + ', <Global Offset>'
                        else:
                            disassembly_end = ''
                            if GetOperandValue(ea, 1) != -1:
                                disassembly_end = disassembly[disassembly.index(','):]
                            disassembly = mnem + (' ' * (8 - len(mnem))) + '<Global Offset>' + disassembly_end
                        
                if len(reg_to_mask) != 0:
                    for reg in reg_to_mask:
                        #   Figure which operand has the reg offset to mask
                        operand_index = 0
                        if ',' in disassembly:
                            if '[' + reg in disassembly[disassembly.index(','):]:
                                operand_index = 1

                        if ('[' + reg not in disassembly) or (GetOpType(ea, operand_index) not in [OT_BASE_INDEX_DIS, OT_MEMORY_REFERENCE]):
                            continue

                        value = GetOperandValue(ea, operand_index)
                        if value > 0x7f or (GetOpType(ea, operand_index) == OT_MEMORY_REFERENCE):
                            value = '{0:08x}'.format(value)
                            value = ' '.join([value[-2:], value[4:6], value[2:4], value[:2]])
                            masked_value = '{4}'
                            if value in instr_opcodes:
                                instr_opcodes = instr_opcodes.replace(value, '{4}')

                            elif 0x80000000 & GetOperandValue(ea, operand_index):
                                value = '{0:02x}'.format(0xFF & GetOperandValue(ea, operand_index))
                                if 1 == operand_index:
                                    if instr_opcodes.endswith(value):
                                        instr_opcodes = instr_opcodes.replace(value, '??')
                                    else:
                                        print 'Unhandled Instruction. Report to developers:'
                                        print disassembly, instr_opcodes, value

                                else:
                                    instr_opcodes = instr_opcodes[:4] + instr_opcodes[4:].replace(value, '??')

                            else:
                                print 'Unhandled Instruction. Report to developers:'
                                print disassembly, instr_opcodes, value

                        else:
                            value = '{0:02x}'.format(value)
                            if not instr_opcodes.endswith(value):
                                print 'Unhandled Instruction. Report to developers:'
                                print disassembly, instr_opcodes, value

                            instr_opcodes = instr_opcodes[:-2] + '??'

                        #   Mask the disassembly
                        if operand_index == 1:
                            disassembly = disassembly[:disassembly.index('[')+1] + reg + '+<Offset>]'

                        else:
                            disassembly_end = ''
                            if GetOperandValue(ea, 1) != -1:
                                disassembly_end = disassembly[disassembly.index(','):]
                            disassembly = disassembly[:disassembly.index('[')+1] + reg + '+<Offset>]' + disassembly_end

                mnemonics.append(disassembly)
                opcodes.append(instr_opcodes)

        self.mnemonics = mnemonics
        self.opcodes = opcodes

    def mask_opcodes_tuple(self, options):
        if len(options) == 4:
            self.mask_opcodes({'esp' : options[0], 
                                'ebp' : options[1], 
                                'abs_calls' : options[2], 
                                'global_offsets' : options[3]})

    def get_save_data_tuple(self):
        mask_tuple = (self.mask_options['esp'], 
                        self.mask_options['ebp'],
                        self.mask_options['abs_calls'],
                        self.mask_options['global_offsets'])
        return (self.start_ea, self.end_ea, mask_tuple, self.custom)

    @staticmethod
    def sub_signature_string(opcodes):
        return ''.join(opcodes).replace(' ', '')

class MiscAssembly(Assembly):
    def __init__(self, data):
        self.mnemonics = None
        self.opcodes= data.split('\n')

    def mask_opcodes(mask_options):
        pass

    def set_opcode_list(self, new_opcodes):
        self.opcodes = new_opcodes

    def get_save_data_tuple(self):
        return (None, None, None, self.get_opcode_list())


#   Dialog GUI Logic
#   
#   These dialogs should have no direct interactions with IDA, allowing it to 
#   be pulled out to other applications or replaced in the future. 
#-------------------------------------------------------------------------------
class AsmSig_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Assembly to Signature')
        Dialog.resize(732, 387)

        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)
        
        #   Opcodes GUI Area
        self.opcode_groupbox = QtGui.QGroupBox()
        sizePolicy.setHeightForWidth(self.opcode_groupbox.sizePolicy().hasHeightForWidth())
        self.opcode_groupbox.setSizePolicy(sizePolicy)
        self.opcode_groupbox.setFixedWidth(200)
        self.opcode_groupbox.setObjectName('opcode_groupbox')
        self.opcode_groupbox.setTitle('Opcodes')
        self.opcodes = QtGui.QPlainTextEdit(self.opcode_groupbox)
        self.opcodes.setReadOnly(True)
        self.opcodes.setLineWrapMode(QtGui.QPlainTextEdit.LineWrapMode.NoWrap)
        font = self.opcodes.document().defaultFont()
        font.setPointSize(12)
        font.setFamily('fixedsys,Liberation Mono')
        self.opcodes.document().setDefaultFont(font)
        self.vbox_opcodes = QtGui.QVBoxLayout(self.opcode_groupbox)
        self.vbox_opcodes.setContentsMargins(1, 1, 1, 1)
        self.vbox_opcodes.addWidget(self.opcodes)
        self.scrollbar_opcodes = self.opcodes.verticalScrollBar()

        #   Assembly GUI Area
        self.asm_groupbox = QtGui.QGroupBox()
        sizePolicy.setHeightForWidth(self.asm_groupbox.sizePolicy().hasHeightForWidth())
        self.asm_groupbox.setSizePolicy(sizePolicy)
        self.asm_groupbox.setObjectName('asm_groupbox')
        self.asm_groupbox.setTitle('Assembly')
        self.asm = QtGui.QPlainTextEdit(self.asm_groupbox)
        self.asm.setReadOnly(True)
        self.asm.setLineWrapMode(QtGui.QPlainTextEdit.LineWrapMode.NoWrap)
        self.asm.document().setDefaultFont(font)
        self.vbox_asm = QtGui.QVBoxLayout(self.asm_groupbox)
        self.vbox_asm.setContentsMargins(1, 1, 1, 1)
        self.vbox_asm.addWidget(self.asm)

        #   Masking Options Area
        self.mask_options = QtGui.QGroupBox()
        sizePolicy.setHeightForWidth(self.mask_options.sizePolicy().hasHeightForWidth())
        self.mask_options.setSizePolicy(sizePolicy)
        self.mask_options.setObjectName('mask_options')
        self.mask_options.setTitle('Mask Options')

        self.vbox_mask = QtGui.QVBoxLayout(self.mask_options)
        self.esp_checkbox = QtGui.QCheckBox(self.mask_options)
        self.esp_checkbox.setObjectName('esp_mask_checkbox')
        self.vbox_mask.addWidget(self.esp_checkbox)
        self.esp_checkbox.setText('ESP Offsets')

        self.ebp_checkbox = QtGui.QCheckBox(self.mask_options)
        self.ebp_checkbox.setObjectName('ebp_mask_checkbox')
        self.vbox_mask.addWidget(self.ebp_checkbox)
        self.ebp_checkbox.setText('EBP Offsets')

        self.abs_call_checkbox = QtGui.QCheckBox(self.mask_options)
        self.abs_call_checkbox.setObjectName('abs_call_mask_checkbox')
        self.vbox_mask.addWidget(self.abs_call_checkbox)
        self.abs_call_checkbox.setText('Absolute Calls')

        self.global_offsets_checkbox = QtGui.QCheckBox(self.mask_options)
        self.global_offsets_checkbox.setObjectName('reg_mask_checkbox')
        self.vbox_mask.addWidget(self.global_offsets_checkbox)
        self.global_offsets_checkbox.setText('Global Offsets')
        
        self.custom_checkbox = QtGui.QCheckBox(self.mask_options)
        self.custom_checkbox.setObjectName('custom_mask_checkbox')
        self.vbox_mask.addWidget(self.custom_checkbox)
        self.custom_checkbox.setText('Customize')
        
        self.vbox_mask.addWidget(self.esp_checkbox)
        self.vbox_mask.addWidget(self.ebp_checkbox)
        self.vbox_mask.addWidget(self.abs_call_checkbox)
        self.vbox_mask.addWidget(self.global_offsets_checkbox)
        self.vbox_mask.addWidget(self.custom_checkbox)

        #   Top Horizontal Layout:  |  Opcodes | Assembly | Masking Options |
        self.hbox_top_data = QtGui.QHBoxLayout()
        self.hbox_top_data.setObjectName('hbox_top_data')
        self.hbox_top_data.addWidget(self.opcode_groupbox)
        self.hbox_top_data.addWidget(self.asm_groupbox)
        self.scrollbar_asm = self.asm.verticalScrollBar()
        self.hbox_top_data.addWidget(self.mask_options)

        #   Analyst's Notes Area
        self.notes = QtGui.QPlainTextEdit()
        self.notes.document().setDefaultFont(font)
        self.notes.setTabChangesFocus(True)
        self.notes.setFixedHeight(100)

        #   Bottom Horizontal Layout: | Error Msg | OK Button | Cancel Button |
        error_font = QtGui.QFont()
        error_font.setBold(True)
        self.error_msg = QtGui.QLabel('')
        self.error_msg.setFont(error_font)
        self.ok_button = QtGui.QPushButton('OK')
        self.ok_button.setFixedWidth(85)
        self.cancel_button = QtGui.QPushButton('Cancel')
        self.cancel_button.setFixedWidth(100)
        self.hbox_bottom = QtGui.QHBoxLayout()
        self.hbox_bottom.addWidget(self.error_msg)
        self.hbox_bottom.addWidget(self.ok_button)
        self.hbox_bottom.addWidget(self.cancel_button)

        #   Vertical Layout
        self.vbox_outer = QtGui.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addLayout(self.hbox_top_data)
        self.vbox_outer.addWidget(QtGui.QLabel('Notes:'))
        self.vbox_outer.addWidget(self.notes)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        QtCore.QObject.connect(self.ok_button, QtCore.SIGNAL('clicked(bool)'), Dialog.ok_button_callback)
        QtCore.QObject.connect(self.cancel_button, QtCore.SIGNAL('clicked(bool)'), Dialog.reject)
        QtCore.QObject.connect(self.scrollbar_opcodes, QtCore.SIGNAL("valueChanged(int)"), Dialog.sync_scrolls)
        QtCore.QObject.connect(self.scrollbar_asm, QtCore.SIGNAL("valueChanged(int)"), Dialog.sync_scrolls)
        QtCore.QObject.connect(self.esp_checkbox, QtCore.SIGNAL("stateChanged(int)"), Dialog.apply_mask)
        QtCore.QObject.connect(self.ebp_checkbox, QtCore.SIGNAL("stateChanged(int)"), Dialog.apply_mask)
        QtCore.QObject.connect(self.abs_call_checkbox, QtCore.SIGNAL("stateChanged(int)"), Dialog.apply_mask)
        QtCore.QObject.connect(self.global_offsets_checkbox, QtCore.SIGNAL("stateChanged(int)"), Dialog.apply_mask)
        QtCore.QObject.connect(self.custom_checkbox, QtCore.SIGNAL("stateChanged(int)"), Dialog.toggle_custom_ui)

class MiscSig_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Create Custom ClamAV Sub Signature')
        Dialog.resize(532, 287)

        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)

        #   ClamAV Sub Signature GUI Area
        self.sig_groupbox = QtGui.QGroupBox()
        sizePolicy.setHeightForWidth(self.sig_groupbox.sizePolicy().hasHeightForWidth())
        self.sig_groupbox.setSizePolicy(sizePolicy)
        self.sig_groupbox.setObjectName('sig_groupbox')
        self.sig_groupbox.setTitle('ClamAV Sub Signature')
        self.sub_signature = QtGui.QPlainTextEdit(self.sig_groupbox)
        font = self.sub_signature.document().defaultFont()
        font.setPointSize(12)
        font.setFamily('fixedsys')
        self.sub_signature.document().setDefaultFont(font)
        self.sub_signature.setTabChangesFocus(True)
        self.vbox_sub_signature = QtGui.QVBoxLayout(self.sig_groupbox)
        self.vbox_sub_signature.setContentsMargins(1, 1, 1, 1)
        self.vbox_sub_signature.addWidget(self.sub_signature)

        #   Middle Horizontal Layout:  |  Notes Label | View As Combo box |
        self.view_as_combobox = QtGui.QComboBox()
        self.view_as_combobox.setFixedWidth(75)
        self.hbox_middle = QtGui.QHBoxLayout()
        self.hbox_middle.addWidget(QtGui.QLabel('Notes:'))
        self.hbox_middle.addStretch(1)
        self.hbox_middle.addWidget(QtGui.QLabel('View As: '))
        self.hbox_middle.addWidget(self.view_as_combobox)

        #   Analyst's Notes Area
        self.notes = QtGui.QPlainTextEdit()
        self.notes.setTabChangesFocus(True)
        self.notes.setFixedHeight(100)
        self.notes.document().setDefaultFont(font)

        #   Bottom Horizontal Layout: | Error Msg | OK Button | Cancel Button |
        error_font = QtGui.QFont()
        error_font.setBold(True)
        self.error_msg = QtGui.QLabel('')
        self.error_msg.setFont(error_font)
        self.ok_button = QtGui.QPushButton('OK')
        self.ok_button.setFixedWidth(85)
        self.cancel_button = QtGui.QPushButton('Cancel')
        self.cancel_button.setFixedWidth(100)
        self.hbox_bottom = QtGui.QHBoxLayout()
        self.hbox_bottom.addWidget(self.error_msg)
        self.hbox_bottom.addWidget(self.ok_button)
        self.hbox_bottom.addWidget(self.cancel_button)

        #   Vertical Layout
        self.vbox_outer = QtGui.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addWidget(self.sig_groupbox)
        self.vbox_outer.addLayout(self.hbox_middle)
        self.vbox_outer.addWidget(self.notes)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        QtCore.QObject.connect(self.ok_button, QtCore.SIGNAL('clicked(bool)'), Dialog.ok_button_callback)
        QtCore.QObject.connect(self.cancel_button, QtCore.SIGNAL('clicked(bool)'), Dialog.reject)

class SubmitSig_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Submit Your ClamAV Signature')
        Dialog.resize(430, 300)

        #   Email Body Area
        self.link = QtGui.QLabel('')
        self.link.setTextFormat(Qt.RichText)
        self.link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.link.setOpenExternalLinks(True)
        self.email_body = QtGui.QPlainTextEdit()
        self.email_body.setReadOnly(True)

        #   Ok Button Area
        self.button_box = QtGui.QDialogButtonBox()
        self.button_box.setOrientation(Qt.Horizontal)
        self.button_box.setStandardButtons(QtGui.QDialogButtonBox.Ok)
        self.button_box.setObjectName('button_box')
        self.hbox_bottom = QtGui.QHBoxLayout()
        self.hbox_bottom.addWidget(self.button_box)

        #   Vertical Layout
        self.vbox_outer = QtGui.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addWidget(self.link)
        self.vbox_outer.addWidget(self.email_body)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        QtCore.QObject.connect(self.button_box, QtCore.SIGNAL('accepted()'), Dialog.accept)
                

#   Class to interface with Dialog GUIs and the back end data
#-------------------------------------------------------------------------------
class CASCDialog(QtGui.QDialog):
    error_format = '<font color="#ff0000">{0}</font>'
    def __init__(self, parent):
        super(CASCDialog, self).__init__(parent)
        self.data = None
        self.should_show = True

    def opcodes_text_changed(self):
        pass

    def set_custom_opcode_list(self, opcodes):
        self.data.set_opcode_list(opcodes)

    def registerSuccessCallback(self, fn):
        self.callback_fn = fn

    def success_callback(self):
        if self.callback_fn != None:
            self.callback_fn(self.data, self.ui.notes.toPlainText(), self.index)
    
    def ok_button_callback(self):
        if None != self.data:
            msg = verify_clamav_sig(self.data.opcode_to_signatrue())
            if None != msg:
                self.ui.error_msg.setText(self.error_format.format(msg))
                return
            
        self.accept()

    def show(self):
        if self.should_show:
            super(CASCDialog, self).show()

class AsmSignatureDialog(CASCDialog):
    def __init__(self, parent, start_ea=BADADDR, end_ea=BADADDR, index=None):
        super(AsmSignatureDialog, self).__init__(parent)

        self.old_scroll_value = 0
        self.callback_fn = None
        self.index = index

        self.ui = AsmSig_Dialog()
        self.ui.setupUi(self)

        self.accepted.connect(self.success_callback)
        self.ui.opcodes.textChanged.connect(self.opcodes_text_changed)

        #   Get Opcodes
        if (BADADDR == start_ea) or (BADADDR == end_ea):
            #   Check if user has selected a chunk of code
            if (BADADDR != SelStart()) and (BADADDR != SelEnd()):
                start_ea, end_ea = (SelStart(), SelEnd())

            #   Check if user has selected a basic block 
            elif get_func(ScreenEA()):
                block = get_block(ScreenEA())
                if None != block:
                    start_ea = block.startEA
                    end_ea = block.endEA

        if ((BADADDR != start_ea) and is_in_sample_segments(start_ea) and 
            (BADADDR != end_ea) and is_in_sample_segments(end_ea - 1)):
                self.data = Assembly(start_ea, end_ea)  
                self.update_opcodes_and_asm()

        else:
            msg_box = QtGui.QMessageBox()
            msg_box.setIcon(QtGui.QMessageBox.Critical)
            msg_box.setWindowTitle('Cannot add Assembly to ClamAV Signature Creator')
            msg_str = ( 'Address range is not within the sample\'s '
                        'segments (0x{0:x} - 0x{1:x})')
            msg_box.setText(msg_str.format(start_ea, end_ea))
            msg_box.exec_()

            self.should_show = False

    def sync_scrolls(self, value):
        if value != self.ui.scrollbar_opcodes.value():
            self.ui.scrollbar_opcodes.setValue(value)
        if value != self.ui.scrollbar_asm.value():
            self.ui.scrollbar_asm.setValue(value)

        self.old_scroll_value = value

    def set_mask(self, mask_tuple):
        if len(mask_tuple) == 4:
            if mask_tuple[0]:
                self.ui.esp_checkbox.setChecked(True)
            if mask_tuple[1]:
                self.ui.ebp_checkbox.setChecked(True)
            if mask_tuple[2]:
                self.ui.abs_call_checkbox.setChecked(True)
            if mask_tuple[3]:
                self.ui.global_offsets_checkbox.setChecked(True)

            self.data.mask_opcodes_tuple(mask_tuple)

    def apply_mask(self, value):
        mask_options = {'esp' : self.ui.esp_checkbox.isChecked(),
                        'ebp' : self.ui.ebp_checkbox.isChecked(),
                        'abs_calls' : self.ui.abs_call_checkbox.isChecked(),
                        'global_offsets' : self.ui.global_offsets_checkbox.isChecked()}

        scroll_value = self.old_scroll_value

        self.data.mask_opcodes(mask_options)

        self.toggle_custom_ui()
        self.update_opcodes_and_asm()
        self.sync_scrolls(scroll_value)

    def toggle_custom_ui(self, is_custom=False):
        if is_custom or self.ui.custom_checkbox.isChecked():
            #   Disable selecting other mask options
            self.ui.esp_checkbox.setEnabled(False)
            self.ui.ebp_checkbox.setEnabled(False)
            self.ui.abs_call_checkbox.setEnabled(False)
            self.ui.global_offsets_checkbox.setEnabled(False)

            #   Disable asm qplaintextedit
            self.ui.asm.setEnabled(False)

            #   Enable editing opcodes qplaintextedit
            self.ui.opcodes.setReadOnly(False)

            if is_custom:
                #   Disconnect checkbox signal to prevent reentry
                QtCore.QObject.disconnect(self.ui.custom_checkbox, 
                                            QtCore.SIGNAL("stateChanged(int)"), 
                                            self.toggle_custom_ui)
                self.ui.custom_checkbox.setChecked(True)
                QtCore.QObject.connect(self.ui.custom_checkbox, 
                                        QtCore.SIGNAL("stateChanged(int)"), 
                                        self.toggle_custom_ui)

        else:
            #   Enable selecting other mask options
            self.ui.esp_checkbox.setEnabled(True)
            self.ui.ebp_checkbox.setEnabled(True)
            self.ui.abs_call_checkbox.setEnabled(True)
            self.ui.global_offsets_checkbox.setEnabled(True)

            #   Enable  asm qplaintextedit
            self.ui.asm.setEnabled(True)

            #   Disble editing opcodes qplaintextedit
            self.ui.opcodes.setReadOnly(True)

            #   Restore opcodes to match 
            self.data.mask_opcodes({})
            self.update_opcodes_and_asm()

    def set_custom_opcode_list(self, opcodes):
        self.data.set_opcode_list(opcodes, True)
        self.toggle_custom_ui(True)

    def update_opcodes_and_asm(self):
        self.ui.opcodes.setPlainText('\n'.join(self.data.get_opcode_list()))
        self.ui.asm.setPlainText('\n'.join(self.data.get_mnemonics_list()))

        #   Set scroll values back to their old values
        self.ui.scrollbar_opcodes.setValue(self.old_scroll_value)
        self.ui.scrollbar_asm.setValue(self.old_scroll_value)

    def opcodes_text_changed(self):
        if self.ui.custom_checkbox.isChecked():
            self.data.set_opcode_list(self.ui.opcodes.toPlainText().split('\n'), True)

class MiscSignatureDialog(CASCDialog):
    view_as_options = ['Hex', 'ASCII', 'Unicode']
    msg = '<font color="#ff0000">{0} Error: {1}</font>'
    conversion_funcs = [lambda x: x.replace(' ', '').decode('hex'),
                        lambda x: unicode(x.replace(' ', '').decode('hex'))]

    def __init__(self, parent, index=None, data=None, notes=None):
        super(MiscSignatureDialog, self).__init__(parent)

        self.index = index
        self.callback_fn = None
        self.conversion_error = False

        self.ui = MiscSig_Dialog()
        self.ui.setupUi(self)

        if None != data:
            self.ui.sub_signature.setPlainText(data)

        if None != notes:
            self.ui.notes.setPlainText(notes)

        self.data = MiscAssembly(self.ui.sub_signature.toPlainText())

        self.accepted.connect(self.success_callback)
        self.ui.sub_signature.textChanged.connect(self.opcodes_text_changed)

        #   Setup combobox GUI component
        for view_as in self.view_as_options:
            self.ui.view_as_combobox.addItem(view_as)
        self.ui.view_as_combobox.setCurrentIndex(0)
        self.ui.view_as_combobox.currentIndexChanged.connect(self.update_opcodes_and_asm)

    def opcodes_text_changed(self):
        current_index = self.ui.view_as_combobox.currentIndex()
        if current_index == self.view_as_options.index('Hex'):
            self.data.set_opcode_list(self.ui.sub_signature.toPlainText().split('\n'))

    def update_opcodes_and_asm(self, view=0):
        opcodes = self.data.get_opcode_list()
        hex_index = self.view_as_options.index('Hex')

        if view == self.view_as_options.index('ASCII'):
            try:
                opcodes = map(self.conversion_funcs[0], opcodes)

                self.ui.sub_signature.setReadOnly(True)
                self.ui.sub_signature.setEnabled(False)

            except Exception as e:
                self.conversion_error = True
                self.ui.error_msg.setText(self.msg.format('ASCII', str(e)))
                self.ui.view_as_combobox.setCurrentIndex(hex_index)
                return

        elif view == self.view_as_options.index('Unicode'):
            try:
                opcodes = map(self.conversion_funcs[1], opcodes)

                self.ui.sub_signature.setReadOnly(True)
                self.ui.sub_signature.setEnabled(False)

            except Exception as e:
                self.conversion_error = True
                self.ui.error_msg.setText(self.msg.format('Unicode', str(e)))
                self.ui.view_as_combobox.setCurrentIndex(hex_index)
                return

        else:
            self.ui.sub_signature.setReadOnly(False)
            self.ui.sub_signature.setEnabled(True)

        #   Set conversion error to False to prevent msg from hanging around
        if self.conversion_error:
            self.conversion_error = False
        else:
            self.ui.error_msg.setText('')

        self.ui.sub_signature.setPlainText('\n'.join(opcodes))

class SubmitSigDialog(QtGui.QDialog):
    def __init__(self, parent, signature, notes):
        super(SubmitSigDialog, self).__init__(parent)

        self.callback_fn = None

        self.ui = SubmitSig_Dialog()
        self.ui.setupUi(self)

        data = ('ClamAV,\n\n'
                'I\'ve created a ClamAV Signature ({0}) with the IDA Pro '
                'ClamAV Signature Creator plugin. Please FP test and publish '
                'if it passes.\n\n'
                'Sample MD5: {1}\n'
                'Signature:\n{2}\n\n'
                'Notes:\n{3}\n\n'
                'Thanks.'
                )

        for i in xrange(len(notes)):
            if (None != notes[i][0]) and (0 < len(notes[i][0])):
                notes[i] = (' (0x{0[0]:x}, 0x{0[1]:x})'.format(notes[i][0]), notes[i][1])
            notes[i] = 'Sig{0}{1[0]}:\n{1[1]}\n'.format(i, notes[i])
        notes_str = ('\n' + '-' * 40 + '\n').join(notes)

        self.ui.email_body.setPlainText(data.format(GetInputFilePath(), 
                                        GetInputMD5(), signature, notes_str))

        link_text = ('Send the below to <a href="mailto:community-sigs@lists.'
                        'clamav.net?Subject={0}&Body={1}">community-sigs@lists'
                        '.clamav.net</a>')

        data = data.format(GetInputFilePath(), GetInputMD5(),
                                        signature, quote_plus(notes_str))
        link_data = link_text.format('Community Signature Submission', data)
        self.ui.link.setText(link_data)
        

#   Model class that contains all of the sub signatures contained in this IDB 
#   file. The model is initialized when the plugin is initialized from an IDC 
#   array stored inside of the IDB file, so sub signatures are persistent across
#   IDA instances as long as the IDB is saved after changes are made.
#-------------------------------------------------------------------------------
class SubSignatureModel(QtCore.QAbstractTableModel):
    def __init__(self, parent = None):
        super(SubSignatureModel, self).__init__(parent)

        self.next_index = 0
        self.index_lookup_table = []

        #   Initialize from netnodes in IDB file
        self.sigs_db = GetArrayId('sub_signatures')
        if self.sigs_db == -1:
            self.sigs_db = CreateArray('sub_signatures')

        self.sub_signatures = collections.OrderedDict()

        index = GetFirstIndex(AR_STR, self.sigs_db)
        while index != -1:
            entry = pickle.loads(GetArrayElement(AR_STR, self.sigs_db, index))
            self.sub_signatures[index] = entry
            self.next_index = index
            self.index_lookup_table.append(index)
            index = GetNextIndex(AR_STR, self.sigs_db, index)

        self.next_index += 1
        print '[CASCPlugin] Loaded %d sub signatures' % len(self.sub_signatures)
        
    def rowCount(self, index=QtCore.QModelIndex()):
        return len(self.sub_signatures)

    def columnCount(self, index=QtCore.QModelIndex()):
        return 4

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None

        if not 0 <= index.row() < len(self.sub_signatures):
            return None

        if role == Qt.DisplayRole:
            row = self.sub_signatures.values()[index.row()]
            ((start_ea, end_ea, mask_options, custom), notes) = row

            if index.column() == 0:
                if None == start_ea:
                    return '-'
                return '0x{0:08x}'.format(start_ea)

            elif index.column() == 1:
                if None == end_ea:
                    return '-'
                return '0x{0:08x}'.format(end_ea)

            elif index.column() == 2:
                return notes

            elif index.column() == 3:
                if None != mask_options:
                    temp = Assembly(start_ea, end_ea)
                    temp.mask_opcodes_tuple(mask_options)

                    if None != custom:
                        temp.set_opcode_list(custom, True)

                    return ''.join(temp.get_opcode_list()).replace(' ', '')

                return MiscAssembly.sub_signature_string(custom)

            else:
                return None

        if role == Qt.FontRole:
            return QtGui.QFont().setPointSize(30)

        if role == Qt.DecorationRole and index.column() == 0:
            return None

        if role == Qt.TextAlignmentRole:
            if index.column() < 2:
                return Qt.AlignCenter;
            return Qt.AlignLeft;

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None

        if orientation == Qt.Horizontal:
            if section == 0:
                return 'Start Address'
            elif section == 1:
                return 'End Address'
            elif section == 2:
                return 'Notes'
            elif section == 3:
                return 'Sub Signature'
            else:
                return None

    def remove_sub_signature(self, row_index):
        if row_index < len(self.index_lookup_table):
            index = self.index_lookup_table[row_index]
            del self.sub_signatures[index]
            del self.index_lookup_table[row_index]
            self.removeRow(row_index)

            #   Delete from IDB
            DelArrayElement(AR_STR, self.sigs_db, index)

    def add_sub_signature(self, sub_sig_data, notes, index=None):
        element =  (sub_sig_data.get_save_data_tuple(), notes)

        if None == index:
            index = self.next_index
            self.next_index += 1

        pos = bisect.bisect(self.sub_signatures.keys(), index)
        if index not in self.sub_signatures:
            #   Add a new element
            self.beginInsertRows(QtCore.QModelIndex(), pos, pos)
            self.sub_signatures[index] = element
            sorted_data = sorted(self.sub_signatures.iteritems(), key=lambda x: x[0])
            self.sub_signatures = collections.OrderedDict(sorted_data)
            self.endInsertRows()

        else:
            #   Modify existing element
            self.sub_signatures[index] = element

        #   Add to IDB
        SetArrayString(self.sigs_db, index, pickle.dumps(element))
        self.index_lookup_table.append(index)

    def update_sub_signature(self, sub_sig_data, notes, row_index):
        element =  (sub_sig_data.get_save_data_tuple(), notes)
        index = self.index_lookup_table[row_index]
        
        #   Update in IDB
        self.sub_signatures[index] = element
        SetArrayString(self.sigs_db, index, pickle.dumps(element))
        
    def get_row_original_data(self, row_index):
        if row_index < len(self.index_lookup_table):
            return self.sub_signatures[self.index_lookup_table[row_index]]


#   Main Plug-in Form Class
#-------------------------------------------------------------------------------
class SignatureCreatorFormClass(PluginForm):
    system = {0 : 'Unknown', 1 : 'Win', 6 : 'Linux', 9 : 'Osx'}

    def __init__(self):
        super(SignatureCreatorFormClass, self).__init__()

    def OnCreate(self, form):
        global add_sig_handler_in_menu

        self.form = form
        self.parent = self.FormToPySideWidget(form)
        self.populate_model()
        self.populate_main_form()

        system = self.system[get_file_type()]
        self.sample_name.setPlainText('{0}.Trojan.Agent'.format(system))

        self.icon = get_clamav_icon()
        #self.parent.setWindowIcon(self.icon)
        try:
            self.grand_parent = self.parent.parent()
            self.grand_parent.setWindowIcon(get_clamav_icon())
        except:
            #   This is an error in PySide/FromCObject that can cause the 
            #   grand_parent's refcount to be 0 and deleted
            pass

    def get_selected_rows(self):
        rows = self.tableview.selectionModel().selectedIndexes()
        if len(rows) == 0:
            return None

        return [self.sub_signature_model.data(item) for item in rows]

    def delete_item(self):
        #   Delete the row from the IDB, in memory structures and repaint table
        for index in self.tableview.selectionModel().selectedRows():
            self.sub_signature_model.remove_sub_signature(index.row())
            self.tableview.reset()

    def copy_item(self):
        item = self.get_selected_rows()
        if item != None:
            to_copy = u' '.join([unicode(x) for x in item])
            QtGui.QApplication.clipboard().setText(to_copy)

    def insert_asm_item(self, ctx=None):
        self.Show('ClamAV Signature Creator')
        dialog = AsmSignatureDialog(self.parent)
        dialog.registerSuccessCallback(self.sub_signature_model.add_sub_signature)
        dialog.setModal(True)
        dialog.show() 

    def insert_string_item(self, ctx):
        #   Get IDA's toplevel chooser widget
        chooser = self.FormToPySideWidget(ctx.form)

        #   Get the embedded table view
        table_view = chooser.findChild(QtGui.QTableView)
        sort_order = table_view.horizontalHeader().sortIndicatorOrder()
        sort_column = table_view.horizontalHeader().sortIndicatorSection()

        #   Get the table view's data
        model = table_view.model()
        sel = ctx.chooser_selection

        data = {}
        for row_data in table_view.selectionModel().selectedRows():
            index = row_data.row()

            address = model.data(model.index(index, 0), Qt.DisplayRole)
            address = int(address[address.index(':')+1:], 16)
            length = model.data(model.index(index, 1), Qt.DisplayRole)
            
            #   Don't inclue the \0 character
            length = int(length, 16) - 1
            if model.data(model.index(index, 2), Qt.DisplayRole) != 'C':
                length -= 1

            raw = ['{0:02x}'.format(Byte(address + i)) for i in xrange(length)]

            data[address] = ' '.join(raw)

        sub_signature = map(lambda x: data[x], sorted(data.keys()))
        try:
            notes = map(lambda x: x.replace(' ', '').decode('hex'), sub_signature)
            notes = map(unicode, notes)
        except UnicodeDecodeError:
            pass

        self.insert_custom_item(' * '.join(sub_signature), '\n'.join(notes))

    def insert_custom_item(self, data=None, notes=None):
        self.Show('ClamAV Signature Creator')
        dialog = MiscSignatureDialog(self.parent, data=data, notes=notes)
        dialog.registerSuccessCallback(self.sub_signature_model.add_sub_signature)
        dialog.setModal(True)
        dialog.show() 

    def export_all(self):
        filename = QtGui.QFileDialog.getSaveFileName(self.parent, 'Save CSV export to...')
        if filename == None:
            return

        num_rows = self.sub_signature_model.rowCount()
        num_columns = self.sub_signature_model.columnCount()
        f = open(filename[0], 'wb')

        csvout = csv.writer(f)
        #   Write header to CSV and then each row
        csvout.writerow([self.sub_signature_model.headerData(x, Qt.Horizontal) for x in xrange(0, num_columns)])
        for row in xrange(0, num_rows):
            column_data = [self.sub_signature_model.index(row, column) for column in xrange(0, num_columns)]
            csvout.writerow([self.sub_signature_model.data(index) for index in column_data])
        print '[CASCPlugin] Exported %d sub signatures to %s' % (num_rows, str(filename[0]))
        f.close()

    def populate_model(self):
        self.sub_signature_model = SubSignatureModel()

    def populate_main_form(self):
        layout = QtGui.QVBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        tableview = QtGui.QTableView()
        tableview.setModel(self.sub_signature_model)
        tableview.setSortingEnabled(False)
        tableview.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)
        tableview.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        tableview.setAlternatingRowColors(True)
        tableview.setShowGrid(False)
        hdr = tableview.verticalHeader()
        hdr.setHighlightSections(False)
        hdr.setDefaultSectionSize(hdr.minimumSectionSize())
        hdr = tableview.horizontalHeader()
        hdr.setHighlightSections(False)
        hdr.setDefaultAlignment(Qt.AlignLeft)
        hdr.setStretchLastSection(True)

        #   Context Menu Setup
        copy_action = QtGui.QAction('&Copy', self.parent)
        copy_action.setShortcut('Ctrl+C')
        insert_action = QtGui.QAction('&Insert', self.parent)
        insert_action.setShortcut('Ins')
        insert_assembly_action = QtGui.QAction('&Insert Assembly', self.parent)
        insert_assembly_action.setShortcut('Ctrl+Ins')
        export_action = QtGui.QAction('E&xport all to CSV...', self.parent)
        export_action.setShortcut('Shift+Ins')
        delete_action = QtGui.QAction('&Delete', self.parent)
        delete_action.setShortcut('Del')
        separator = QtGui.QAction(self.parent)
        separator.setSeparator(True)
        tableview.setColumnWidth(0, 75)
        tableview.setColumnWidth(1, 75)
        tableview.setColumnWidth(2, 300)
        tableview.setContextMenuPolicy(Qt.ActionsContextMenu)
        tableview.addAction(insert_action)
        tableview.addAction(insert_assembly_action)
        tableview.addAction(separator)
        tableview.addAction(copy_action)
        tableview.addAction(export_action)
        tableview.addAction(separator)
        tableview.addAction(delete_action)

        #   Bottom Horizonal Layout: | Sample Name | Create Sig Button |
        generate_button = QtGui.QPushButton('Create ClamAV Signature')
        generate_button.setFixedWidth(160)
        generate_button.clicked.connect(self.generate_signature)
        sample_name_label = QtGui.QLabel('Name:')
        self.sample_name = OneLineQPlainTextEdit()
        self.sample_name.setPlainText('')
        self.sample_name.setFixedHeight(generate_button.sizeHint().height())
        hboxview = QtGui.QHBoxLayout()
        hboxview.setContentsMargins(1, 1, 1, 1)
        hboxview.addWidget(sample_name_label)
        hboxview.addWidget(self.sample_name)
        hboxview.setSpacing(5)
        hboxview.addStretch(1)
        hboxview.addWidget(generate_button)

        #   Add Layouts/Widgets to Main Layout
        layout.addWidget(tableview)
        layout.addLayout(hboxview)
        self.parent.setLayout(layout)

        #   Signal Handling
        copy_action.triggered.connect(self.copy_item)
        insert_action.triggered.connect(self.insert_custom_item)
        insert_assembly_action.triggered.connect(self.insert_asm_item)
        export_action.triggered.connect(self.export_all)
        delete_action.triggered.connect(self.delete_item)
        tableview.doubleClicked.connect(self.row_clicked)

        tableview.resizeColumnsToContents()
        self.tableview = tableview

    def row_clicked(self, index):
        row_index = index.row()
        if row_index < len(self.sub_signature_model.index_lookup_table):
            index = self.sub_signature_model.index_lookup_table[row_index]

            data = self.sub_signature_model.sub_signatures[index]
            (start_ea, end_ea, mask_options, custom_opcodes), notes = data
            if None != start_ea:
                dialog = AsmSignatureDialog(self.parent, start_ea, end_ea, row_index)
                dialog.set_mask(mask_options)

            else:
                dialog = MiscSignatureDialog(self.parent, row_index)

            if None != custom_opcodes:
                dialog.set_custom_opcode_list(custom_opcodes)

            dialog.ui.notes.setPlainText(notes)
            dialog.update_opcodes_and_asm()
            dialog.registerSuccessCallback(self.sub_signature_model.update_sub_signature)
            dialog.setModal(True)
            dialog.show() 

    def generate_signature(self):
        ndb_format = '{0}:{1}:*:{2}'
        ldb_format = '{0};Engine:51-255,Target:{1};{2};{3}'

        msg_box = QtGui.QMessageBox()
        msg_box.setIcon(QtGui.QMessageBox.Critical)
        msg_box.setWindowTitle('Unable to create ClamAV Signature')

        #   Ensure the signature name is valid
        name = self.sample_name.toPlainText()
        if None == re.match('^\w+\.\w+\.\w+(|\.Gen)$', name):
            msg_box.setWindowTitle('Invalid ClamAV Signature Name')
            msg_box.setText(('Could not create ClamAV signature. An invlaid '
                            'signature\n name was provided.\n\nName Format:\n'
                            '<Targeted Platform or File Format>.<Category>.'
                            '<Sample Name>\n\nOptional Suffix: .Gen'))
            return msg_box.exec_()

        #   Get sub signatures that are selected
        sub_sigs = []
        for index in self.tableview.selectionModel().selectedRows():
            sub_sig = self.sub_signature_model.get_row_original_data(index.row())
            if None != sub_sig:
                sub_sigs.append(sub_sig)

        #   Dynamically get the file type 
        file_type = get_file_type()
        signature = None

        if 0 == len(sub_sigs):
            msg_box.setText(('No sub signatures were selected. Select one or\n'
                            'more signatures before creating a ClamAV Signature'))
            return msg_box.exec_()

        #   Get opcodes for all sub signatures
        opcodes = []
        notes = []
        for (start_ea, end_ea, mask_options, custom_opcodes), note in sub_sigs:
            temp_note = ('', note)
            if (None != start_ea) and (None != end_ea) and (None == custom_opcodes):
                obj = Assembly(start_ea, end_ea)
                obj.mask_opcodes_tuple(mask_options)
                custom_opcodes = obj.get_opcode_list()
                temp_note = ((start_ea, end_ea), note)

            elif None == custom_opcodes:
                msg_box.setText(('Saved data is incorrectly formated.\nCould '
                                'not retrieve sub signatures data.'))
                msg_box.exec_()
                continue

            elif (None != start_ea) and (None != end_ea):
                temp_note = ((start_ea, end_ea), note)

            opcodes.append(''.join(custom_opcodes).replace(' ', ''))
            notes.append(temp_note)

        #   Create signature based on opcodes
        if 0 == len(opcodes):
            msg_box.setText('No opcodes to create a sig with')
            return msg_box.exec_()

        elif 1 == len(opcodes):
            #   Create NDB signature
            signature = ndb_format.format(name, file_type, ''.join(opcodes[0]).replace('', ''))
            print 'NDB created from custom_opcodes:\n\t{0}'.format(signature)

        else:
            #   Create LDB signature
            condition = '&'.join(map(str, range(len(sub_sigs))))
            signature = ldb_format.format(name, file_type, condition, ';'.join(opcodes))
            print 'LDB created from custom_opcodes:\n\t{0}'.format(signature)

        #   Display dialog to user
        dialog = SubmitSigDialog(self.parent, signature, notes)
        dialog.setModal(True)
        dialog.show() 

        return signature

    def OnClose(self,form):
        pass


#   ClamAV Signature Creator (CASC) Plug-in Class
#-------------------------------------------------------------------------------
class ClamAVSigCreatorPlugin(plugin_t):
    flags = PLUGIN_FIX
    comment = 'Aids analysts in creating ClamAV NDB and LDB signatures'

    #   IDA Pro display details
    help = 'Creates ClamAV signatures from selected data from an IDB'
    wanted_name = 'ClamAV Signature Creator'
    wanted_hotkey = '`'

    def init(self):
        global clamav_sig_creator_plugin

        file_type = GetCharPrm(INF_FILETYPE)

        #   Currently only supports intel_x86
        if get_file_type() not in [1, 6, 9]:
            msg_str = '{0} does not support this file type.\n'
            msg(msg_str.format(self.wanted_name))
            return PLUGIN_SKIP

        #   Check to see if we've configured the plug-in yet.
        if not clamav_sig_creator_plugin:
            clamav_sig_creator_plugin = SignatureCreatorFormClass()

        return PLUGIN_OK

    def run(self, arg):
        global clamav_sig_creator_plugin

        if None != clamav_sig_creator_plugin:
            clamav_sig_creator_plugin.Show(self.wanted_name)

    def term(self):
        pass


def PLUGIN_ENTRY():
    global valid_address_ranges
    valid_address_ranges = get_existing_segment_ranges()
    return ClamAVSigCreatorPlugin()
