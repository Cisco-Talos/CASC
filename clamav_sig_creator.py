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
import idaapi
import idc
import idautils
from idaapi import PluginForm, action_handler_t, UI_Hooks, plugin_t, BADADDR, \
                    insn_t, execute_ui_requests, IDA_SDK_VERSION, BWN_DISASMS, \
                    BWN_STRINGS, BWN_IMPORTS, AST_ENABLE_ALWAYS

#   Python Modules
import collections
import bisect
import pickle
import math
import types
import re
import csv
from urllib import quote_plus
try:
    #   For IDA 6.8 and older using PySide
    from PySide import QtGui, QtGui as QtWidgets, QtCore
    from PySide.QtCore import Qt
except ImportError:
    #   For IDA 6.9 and newer using PyQt5
    from PyQt5 import QtGui, QtWidgets, QtCore
    from PyQt5.QtCore import Qt


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

#   IDA Wrapper to ensure thread safety for function calls
#-------------------------------------------------------------------------------
class IDAWrapper(object):
    '''
    Class to wrap functions that are not thread safe
    '''
    def __getattribute__(self, name):
        default = '[1st] default'

        val = getattr(idaapi, name, default)
        if val == default:
            val = getattr(idc, name, default)

        if val == default:
            val = getattr(idautils, name, default)

        if val == default:
            msg = 'Unable to find {}'.format(name)
            print msg
            return

        if hasattr(val, '__call__'):
            def call(*args, **kwargs):
                holder = [None] # need a holder, because 'global' sucks

                def trampoline():
                    holder[0] = val(*args, **kwargs)
                    return 1

                idaapi.execute_sync(trampoline, idaapi.MFF_FAST)
                return holder[0]
            return call

        else:
            return val

IDAW = IDAWrapper()


#   Misc Helper Functions
#-------------------------------------------------------------------------------
def get_file_type():
    #   ClamAV Types: {1 : 'PE', 6 : 'ELF', 9 : 'Mach-O', 0 : 'Any'}
    file_type = IDAW.get_file_type_name()
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

def get_type_name(file_type):
    lookup = {1 : 'PE', 6 : 'ELF', 9 : 'Mach-O', 0 : 'Any'}

    if file_type not in lookup:
        return 'UNKNOWN'

    return lookup[file_type]

def convert_to_ascii(data):
    if data is None:
        return data

    if len(data) != 1:
        return data

    data = data[0].replace(' ', '')
    converted = ''
    not_complete = True
    while not_complete:
        if re.match('^([a-fA-F\d]{2})', data):
            converted += data[:2].decode('hex')
            data = data[2:]

        elif data.startswith('{'):
            match = re.match('^\{(?:(\d+)|(\d+)\-|\-(\d+)|(\d+)\-(\d))\}', data)
            matches =  match.groups()
            if matches[0] is not None:
                length = '=={}'.format(matches[0])
            elif matches[1] is not None:
                length = '>={}'.format(matches[1])
            elif matches[2] is not None:
                length = '<={}'.format(matches[2])
            elif None not in matches [3:]:
                length = '>={}&&<={}'.format(matches[3], matches[4])

            end = data.index('}') + 1
            converted += '{{WILDCARD_ANY_STRING(LENGTH{})}}'.format(length)
            data = data[end:]

        elif re.match('^\[(\d+)\-(\d+)\]', data):
            matches = re.match('^\[(\d+)\-(\d+)\]').groups()
            end = data.index(']') + 1
            converted += '{{WILDCARD_ANY_STRING(LENGTH>={0[0]}&&<={0[1]})}}'.format(matches)
            data = data[end:]

        elif data.startswith('*'):
            converted += '{WILDCARD_ANY_STRING}'
            data = data[1:]

        elif data.startswith('??'):
            converted += '{WILDCARD_IGNORE}'
            data = data[2:]

        elif re.match('^(?:([a-fA-F\d])\?|\?([a-fA-F\d]))', data):
            matches = re.match('^(?:([a-fA-F\d])\?|\?([a-fA-F\d]))').groups()
            temp = '{{WILDCARD_NIBBLE_{}:{}}}'
            if matches[0] is not None:
                temp = temp.format('HIGH', hex(matches[0]))
            else:
                temp = temp.format('LOW', hex(matches[1]))
            converted += temp
            data = data[2:]

        elif data.startswith('('):
            end = data.index(')') + 1
            alternates = convert_to_ascii([data[1:end-1]])

            converted += '{{STRING_ALTERNATIVE:{}}}'.format(alternates)
            data = data[end:]

        else:
            if data[0] not in ['|']:
                print '[CASC] Error: idk how to handle {}'.format(data[0])
            converted += data[0]
            data = data[1:]

        if len(data) == 0:
            not_complete = False

    return converted

def is_32bit():
    info = IDAW.get_inf_structure()
    if info.is_64bit():
        return False
    elif info.is_32bit():
        return True

    return False

def is_64bit():
    info = IDAW.get_inf_structure()
    return info.is_64bit()

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
    sig_format = (  '^('
                        '([\da-fA-F\?]{2})|'
                        '(\{(?:\d+|\-\d+|\d+\-|(?:\d+)\-(?:\d+))\})|'
                        '\*|'
                        '((?:!|)\((?:[\da-fA-F\?]{2})+(?:\|(?:[\da-fA-F\?]{2})+)+\))|'
                        '(\((?:B|L|W)\))|'
                        '(\[\d+\-\d+\])'
                    ')+$')
    pattern = sig_format[2:-3]

    if None == re.match(sig_format, sig):
        return 'Invalid signature, check ClamAV signature documentation'

    matches = map(lambda x: filter(None, x)[0], re.findall(pattern, sig))
    for i in xrange(len(matches)):
        if matches[i].startswith('{'):
            #   Ensure that there are two bytes before and after
            if (i-2 < 0) and  (i+2 >= len(matches)):
                return ('Invalid signature, two hex bytes are not before and '
                        'after {*} expression')

            #   Check bytes before for valid hex strings
            before_check = 0
            for j in  list({max(i-2, 0), max(i-1, 0)}):
                if re.match('[\da-fA-F]{2}', matches[j]):
                    before_check += 1

            #   Check bytes after for valid hex strings
            after_check = 0
            for j in [i+1, i+2]:
                if re.match('[\da-fA-F]{2}', matches[j]):
                    after_check += 1

            if 2 not in [before_check, after_check]:
                return ('Invalid signatrue, hex byte at {0} ({1}) is not '
                        'preceeded or followed by two fixed byte '
                        'values'.format(i, matches[i]))

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
    ea_func = IDAW.get_func(ea)

    #   Ensure ea is in a function
    if ea_func:
        fc = IDAW.FlowChart(ea_func)

        for block in fc:
            #   Check address selected is in the block's range
            if (block.startEA <= ea) and (ea < block.endEA):
                return block

    return None

def get_existing_segment_ranges():
    return map(lambda x: [x.startEA, x.endEA], map(IDAW.getseg, IDAW.Segments()))

def is_in_sample_segments(ea):
    global valid_address_ranges

    for segment_range in valid_address_ranges:
        if segment_range[0] <= ea < segment_range[1]:
            return True

    return False

def get_architecture():
    info = IDAW.get_inf_structure()
    proc = info.procName.lower()
    if 'metapc' == proc:
        proc = 'intel'

    bits = 16
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32

    return (proc, bits)

def get_parser():
    proc, bits = get_architecture()
    mapping = {'intel' : IntelParser}

    if proc in mapping:
        parser = mapping[proc]
        if type(parser) != types.TypeType:
            #   For future use if mapping includes more of a breakdown
            return CASCParser(bits)

        return parser(bits)

    return CASCParser(bits)

def get_gui():
    proc, bits = get_architecture()
    mapping = {'intel' : IntelMask}

    if proc in mapping:
        gui = mapping[proc]
        if type(gui) != types.TypeType:
            #   For future use if mapping includes more of a breakdown
            return CASCMask(bits)

        return gui(bits)

    return CASCMask(bits)


#   Create ClamAV icon
CLAMAV_ICON = get_clamav_icon(True).decode('hex')
CLAMAV_ICON = IDAW.load_custom_icon(data=CLAMAV_ICON, format='png')


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
            tform_type = IDAW.get_tform_type(form)
            if BWN_DISASMS == tform_type:
                IDAW.attach_action_to_popup(form, popup, 'clamav:add_sig')

            elif BWN_STRINGS == tform_type:
                IDAW.attach_action_to_popup(form, popup, 'clamav:add_string')

            elif BWN_IMPORTS == tform_type:
                IDAW.attach_action_to_popup(form, popup, 'clamav:add_import')

        def init_actions(self):
            global CLAMAV_ICON, clamav_sig_creator_plugin

            add_sig_handler = CASCActionHandler(clamav_sig_creator_plugin.insert_asm_item)
            add_sig_action_desc = IDAW.action_desc_t('clamav:add_sig',
                                                'Add Assembly to ClamAV Sig Creator...',
                                                add_sig_handler,
                                                'Ctrl+`',
                                                'From current selection or selected basic block',
                                                CLAMAV_ICON)
            IDAW.register_action(add_sig_action_desc)

            strings_handler = CASCActionHandler(clamav_sig_creator_plugin.insert_string_item)
            strings_action_desc = IDAW.action_desc_t('clamav:add_string',
                                                'Add string to ClamAV Sig Creator',
                                                strings_handler,
                                                None,
                                                'Add current string as sub signature',
                                                CLAMAV_ICON)
            IDAW.register_action(strings_action_desc)

            import_handler = CASCActionHandler(clamav_sig_creator_plugin.insert_import_item)
            import_action_desc = IDAW.action_desc_t('clamav:add_import',
                                                'Add Import to ClamAV Sig Creator',
                                                import_handler,
                                                None,
                                                'Add current import as sub signature',
                                                CLAMAV_ICON)
            IDAW.register_action(import_action_desc)

    hooks = CASCHooks()
    hooks.hook()

except NameError:
    b_asm_sig_handler_loaded = False

#
#   Masking GUI component
#-------------------------------------------------------------------------------
class CASCMask(object):
    def __init__(self, bits):
        self.bits = bits
        self.gui = QtWidgets.QWidget()

    def get_masking(self):
        return []

    def set_masking(self):
        pass

    def register_signals(self, apply_mask_func, custom_ui_func):
        pass

    def disable(self):
        pass

    def enable(self):
        pass

    def set_custom(self, checked):
        pass

    def custom_checked(self):
        pass

class IntelMask(CASCMask):
    def __init__(self, bits):
        super(IntelMask, self).__init__(bits)

        self.maskings = [('ESP Offsets', 'sp_mask'),
                        ('EBP Offsets', 'bp_mask'),
                        ('Call Offsets', 'call_mask'),
                        ('Jump Offsets', 'jmp_mask'),
                        ('Global Offsets', 'global_mask'),
                        ('Customize', 'custom_mask')]
        self.registers = [  ('EAX', 'eax_mask'), ('EBX', 'ebx_mask'),
                            ('ECX', 'ecx_mask'), ('EDX', 'edx_mask'),
                            ('ESI', 'esi_mask'), ('EDI', 'edi_mask')]
        if not is_32bit():
            self.registers = []

        self.gui = self._init_gui()

    def _init_gui(self):
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)

        mask_options = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(mask_options.sizePolicy().hasHeightForWidth())
        mask_options.setSizePolicy(sizePolicy)
        mask_options.setObjectName('mask_options')
        mask_options.setTitle('Mask Options')

        vbox_mask = QtWidgets.QVBoxLayout(mask_options)
        for text, name in self.maskings:
            checkbox = QtWidgets.QCheckBox(text, mask_options)
            checkbox.setObjectName(name)
            vbox_mask.addWidget(checkbox)

        vbox_mask.addStretch()

        if self.registers:
            #   Original Opcodes GUI Area
            reg_groupbox = QtWidgets.QGroupBox()
            sizePolicy.setHeightForWidth(reg_groupbox.sizePolicy().hasHeightForWidth())
            reg_groupbox.setSizePolicy(sizePolicy)
            reg_groupbox.setObjectName('reg_groupbox')
            reg_groupbox.setTitle('Mask Registers')
            hbox_reg = QtWidgets.QHBoxLayout(reg_groupbox)
            vbox_reg = QtWidgets.QVBoxLayout()
            vbox_reg.setContentsMargins(1, 1, 1, 1)
            hbox_reg.addLayout(vbox_reg)
            vbox_mask.addWidget(reg_groupbox)

            for text, name in self.registers:
                if self.registers.index((text, name)) == (len(self.registers)/2):
                    vbox_reg = QtWidgets.QVBoxLayout()
                    vbox_reg.setContentsMargins(1, 1, 1, 1)
                    hbox_reg.addLayout(vbox_reg)

                checkbox = QtWidgets.QCheckBox(text, mask_options)
                checkbox.setObjectName(name)
                vbox_reg.addWidget(checkbox)

        return mask_options

    def get_masking(self):
        checked = [x for x in self.get_non_custom_masks() if x.isChecked()]
        return [x.objectName().replace('_mask', '') for x in checked]

    def set_masking(self, maskings):
        checkboxes = [x[1] for x in self.maskings] + [x[1] for x in self.registers]
        for x in [self.gui.findChild(QtWidgets.QCheckBox, x) for x in checkboxes]:
            name = x.objectName().replace('_mask', '')
            if name in maskings:
                x.setChecked(True)

    def register_signals(self, apply_mask_func, custom_ui_func):
        checkboxes = [x[1] for x in self.maskings] + [x[1] for x in self.registers]
        objs = [self.gui.findChild(QtWidgets.QCheckBox, x) for x in checkboxes]

        for checkbox in objs:
            name = checkbox.objectName()
            if name.startswith('custom'):
                checkbox.stateChanged.connect(custom_ui_func)
            else:
                checkbox.stateChanged.connect(apply_mask_func)

    def disable(self):
        [x.setEnabled(False) for x in self.get_non_custom_masks()]

    def enable(self):
        [x.setEnabled(True) for x in self.get_non_custom_masks()]

    def get_non_custom_masks(self):
        checkboxes = [x[1] for x in self.maskings if not x[1].startswith('custom')]
        checkboxes += [x[1] for x in self.registers]
        return [self.gui.findChild(QtWidgets.QCheckBox, x) for x in checkboxes]

    def custom_checked(self):
        return self.get_custom_checkbox().isChecked()

    def set_custom(self, checked):
        checkbox = self.get_custom_checkbox()

        checkbox.blockSignals(True)
        checkbox.setChecked(checked)
        checkbox.blockSignals(False)

    def get_custom_checkbox(self):
        custom = [x[1] for x in self.maskings if x[1].startswith('custom')][0]
        return self.gui.findChild(QtWidgets.QCheckBox, custom)

#
#   Architecture parsers
#-------------------------------------------------------------------------------
class CASCParser(object):
    def __init__(self, bits):
        self.bits = bits

    def get_gui_layout(self):
        mask_options = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(mask_options.sizePolicy().hasHeightForWidth())
        mask_options.setSizePolicy(sizePolicy)
        mask_options.setObjectName('mask_options')
        mask_options.setTitle('Mask Options')
        vbox_mask = QtWidgets.QVBoxLayout(mask_options)

        raise mask_options

    def set_masking(self):
        pass

    def register_gui_signals(self, gui_obj, apply_mask_func, custom_ui_func):
        pass

    def setEnable(self, gui_obj, is_enabled=False):
        pass

class IntelParser(CASCParser):
    prefixes = '^([\xf0\xf3\xf2\x2e\x36\x3e\x26\x64\x65\x66\x67]{1,4})'
    prefixes_x64 = '^((?:[\xf0\xf3\xf2\x2e\x36\x3e\x26\x64\x65\x66\x67]|\x0f(?:\x38|\x3a){0,1}){1,4})'

    prefix_required_modrm = [6, 8, 9, 0x0b, 0x0d] + range(0x14, 0x18) + \
                            [0x1f, 0x2c, 0x2d] + \
                            [0x40, 0x60, 0x61, 0x68, 0x6a] + \
                            range(0x6c, 0x70) + range(0x71, 0x77) + \
                            range(0x7c, 0x80) + \
                            [0xa3, 0xa4, 0xa5] + range(0xab, 0xb0) + \
                            [0xc2, 0xc3, 0xc8, 0xd4, 0xd5, 0xd7] + \
                            range(0xe0, 0xf0) + [0xf4] + range(0xf8, 0xfe)
    noprefix_nomodrm = [1] + range(0x50, 0x62) + range(0x90, 0x9a) + \
                        range(0xb0, 0xc0)

    two_opcodes = { 1 : range(0xc8, 0xd2) + [0xd5, 0xd6, 0xf8, 0xf9],
                    0xc6 : [0xf8], 0xc7 : [0xf8], 0xd4 : [0xa0], 0xd5 : [0xa0],
                    0xd8 : [0xc0, 0xc8, 0xd0, 0xd1, 0xd8, 0xd9, 0xe0, 0xe8,
                            0xf0, 0xf8],
                    0xd9 : [0xc0, 0xc8, 0xc9, 0xd0, 0xe0, 0xe1, 0xe4, 0xe5,
                            0xe8, 0xe9, 0xea, 0xec, 0xed, 0xee, 0xf0, 0xf1,
                            0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf9, 0xfa,
                            0xfb, 0xfc, 0xfd, 0xfe, 0xff],
                    0xda : [0xc0, 0xc8, 0xd0, 0xd8, 0xe9],
                    0xdb : [0xc0, 0xc8, 0xd0, 0xd8, 0xe2, 0xe3, 0xe8, 0xf0],
                    0xdc : [0xc0, 0xc8, 0xe0, 0xe8, 0xf0, 0xf8],
                    0xdd : [0xc0, 0xd0, 0xd8, 0xe0, 0xe1, 0xe8, 0xe9],
                    0xde : [0xc0, 0xc1, 0xc8, 0xc9, 0xd9, 0xe0, 0xe1, 0xe8,
                            0xe9, 0xf0, 0xf1, 0xf8, 0xf9],
                    0xdf : [0xe0, 0xe8, 0xf0],
                    0x0f : range(0x80,0x90) + [0xc8],
                    0xfa : [0xae]}

    three_opcodes = {0x9b : ['\xd3\xe3', '\xdb\xe2', '\xdf\xe0']}
    two_opcodes_modrm = {0x38 : range(0, 0x0c) + \
                                [0x10, 0x14, 0x15, 0x17, 0x1c, 0x1d, 0x1e] + \
                                range(0x20, 0x26) + [0x28, 0x29, 0x2a, 0x2b] + \
                                range(0x30, 0x42) + [0x82] + \
                                range(0xdb, 0xe0) + [0xf0, 0xf1],
                        0x3a : range(0x08, 0x10) + range(0x14, 0x18) + \
                                range(0x20, 0x23) + range(0x40, 0x45) + \
                                range(0x60, 0x64) + [0xdf],
                        0x9b : [0xd9, 0xdd],
                        0x0f : range(0, 4) + [0x06, 0x0d] + range(0x10, 0x19) + \
                                range(0x1f, 0x24) + [0x2a, 0x2b, 0x2d, 0x2e, 0x2f] + \
                                range(0x40, 0x50) + range(0x51, 0x6c) + \
                                range(0x70, 0x77) + [0x7f, 0xa3, 0xa4, 0xa5] + \
                                range(0xab, 0xb8) + range(0xba, 0xc8) + \
                                range(0xd2, 0xf0) + range(0xf1, 0xf5) + \
                                range(0xf6, 0xff)}

    no_modrm = [0x04, 0x05, 0x07, 0x0c, 0x0e, 0x1c, 0x1d, 0x1e, 0x24, 0x25,
                0x27, 0x34, 0x35, 0x37, 0x3c, 0x3d, 0x3f, 0x77, 0x78, 0x79,
                0x7a, 0x7b, 0x82] + range(0x91, 0xa3) + [0xa6, 0xa7, 0xa8,
                0xa9, 0xaa, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xf5]

    reg_variants = {'eax' : re.compile('([^a-zA-Z_@]|^)(e{0,1}a(?:x|h|l))'),
                    'ebx' : re.compile('([^a-zA-Z_@]|^)(e{0,1}b(?:x|h|l))'),
                    'ecx' : re.compile('([^a-zA-Z_@]|^)(e{0,1}c(?:x|h|l))'),
                    'edx' : re.compile('([^a-zA-Z_@]|^)(e{0,1}d(?:x|h|l))'),
                    'esi' : re.compile('([^a-zA-Z_@]|^)(e{0,1}sil{0,1})'),
                    'edi' : re.compile('([^a-zA-Z_@]|^)(e{0,1}dil{0,1})')}

    reg_exceptions = [(0x0f, 0xc8), 0x48, 0x40, 0xb0, 0xb8, 0x58, 0x50, 0x90]

    bin2reg = { 0b000 : ['eax', 'ax', 'al', 'mmo', 'xmmo'],
                0b001 : ['ecx', 'cx', 'cl', 'mm1', 'xmm1'],
                0b010 : ['edx', 'dx', 'dl', 'mm2', 'xmm2'],
                0b011 : ['ebx', 'bx', 'bl', 'mm3', 'xmm3'],
                0b100 : ['ah', 'mm4', 'xmm4'],
                0b101 : ['ch', 'mm5', 'xmm5'],
                0b110 : ['esi', 'si', 'dh', 'mm6', 'xmm6'],
                0b111 : ['edi', 'di', 'bh', 'mm7', 'xmm7']}

    def __init__(self, bits):
        super(IntelParser, self).__init__(bits)

    def mask_instruction(self, ea, maskings):
        instr = self.parse_instruction(ea)
        m_disassembly = ''
        m_opcodes = [x.encode('hex') for x in [instr['prefix'][0] + instr['opcode'][0]]]

        default = (instr['disassembly'], ' '.join(instr['bytes']))

        #   Call instructions
        #--------------------
        if (instr['opcode'][1] == 'call') and ('call' in maskings):
            #   Mask off absolute/relative call offsets
            masked_imm = '{{{}}}'.format(len(instr['imm'][0]))
            if len(instr['modr/m']) > 1:
                #   Absolute call
                m_opcodes += [instr['modr/m'][0].encode('hex'), masked_imm]
                return ('call    <Absolute Offset>', ' '.join(m_opcodes))

            #   Relative call
            m_opcodes.append(masked_imm)
            return ('call    <Relative Offset>', ' '.join(m_opcodes))

        #   Jcc and JMP instructions
        #---------------------------
        if (instr['opcode'][1].startswith('j')) and ('jmp' in maskings):
            #   Mask off relative jump offsets
            if len(m_opcodes[-1]) > 1:
                m_opcodes +=  [x.encode('hex') for x in m_opcodes[-1].decode('hex')]
                del m_opcodes[-3]
            if len(instr['modr/m']) > 1:
                m_opcodes.append(instr['modr/m'][0].encode('hex'))
            m_opcodes.append('{{{}}}'.format(len(instr['imm'][0])))
            return ('{: <8}<Jump Offset>'.format(instr['opcode'][1]), ' '.join(m_opcodes))

        #-----------------------------------------------------------------
        #   Below multiple maskings can be applied to the same instruction
        #-----------------------------------------------------------------

        #   Prepare structure for masking operands and details.
        opcodes_order = ['prefix', 'opcode', 'modr/m', 'sib', 'disp', 'imm']
        current_opcodes = [instr[x][0] for x in opcodes_order]

        mnem = IDAW.GetMnem(ea)
        operands = default[0][default[0].index(mnem)+len(mnem):].split(',')
        operands = [x.lstrip() for x in operands]
        prefix = ''
        if len(instr['prefix']) > 1:
            prefix = instr['prefix'][1]
        current_disassembly = [prefix, instr['opcode'][1]] + operands

        #   Global offset instructions
        #   A little complicated to do since it could just be a hard coded value
        #-----------------------------------------------------------------------
        if ('global' in maskings) and (len(instr['imm']) > 1):
            #   Assuming the value is a global offset if it exists within a
            #   segment
            #   Since VirtualAlloc uses 0x400000 and many PEs are based at that
            #   address we are going to exclude it
            offset = int(instr['imm'][1][2:].replace('L', ''), 16)
            if (IDAW.getseg(offset) is not None) and (offset != 0x400000):
                imm = current_opcodes[5]
                if len(imm) == 1:
                    current_opcodes[5] = '??'
                else:
                    current_opcodes[5] = '{{{}}}'.format(len(imm))

                for i in xrange(2, len(current_disassembly)):
                    if (('{:x}'.format(offset) in current_disassembly[i].lower())
                        or (IDAW.LocByName(current_disassembly[i]) == offset)):
                        current_disassembly[i] = '<Global Offset>'

        #   SP and BP displacement masking
        #-----------------------------------------------------------------------
        if len(instr['disp']) > 0:
            if len(instr['modr/m']) > 1:
                #   Check the displacement value is from an esp offset
                modrm = instr['modr/m'][1]
                if 0b01 <= modrm['mod'] <= 0b10:
                    mask_disp = ''
                    #   EBP offset
                    if ('bp' in maskings) and (modrm['rm'] == 0b101):
                        mask_disp = 'bp'

                    #   ESP offset
                    if (('sp' in maskings) and (modrm['rm'] == 0b100)
                        and (len(instr['sib']) > 1)):
                        sib = instr['sib'][1]
                        if sib['base'] == 0b100:
                            mask_disp = 'sp'

                    if mask_disp:
                        for i in xrange(2, len(current_disassembly)):
                            x = current_disassembly[i]
                            mask_re = '{}+[^\]]+'.format(mask_disp)
                            value = '{0}+<{1} Offset>'.format(mask_disp, mask_disp.upper())
                            current_disassembly[i] = self.mask_operand(x, mask_re, value)

                        disp = current_opcodes[4]
                        if len(disp) == 1:
                            current_opcodes[4] = '??'
                        else:
                            current_opcodes[4] = '{{{}}}'.format(len(disp))

        #   Register Masking
        #-----------------------------------------------------------------------
        regs = {'eax', 'edx', 'ecx', 'edx', 'esi', 'edi'}.intersection(maskings)
        masked_regs = []
        for reg in regs:
            for i in xrange(2, len(current_disassembly)):
                operand = current_disassembly[i]
                if self.reg_variants[reg].search(operand):
                    current_disassembly[i] = self.reg_variants[reg].sub('\\1<Reg Masked>', operand)
                    masked_reg = self.reg_variants[reg].search(operand).groups()[1]

                    opcode_masked = False
                    current_modrm = current_opcodes[2]
                    original_modrm = instr['modr/m'][0]
                    if len(original_modrm) == 1:
                        modrm = instr['modr/m'][1]

                        minreg = (modrm['mod'] << 6) | 0 | modrm['rm']
                        minrm = (modrm['mod'] << 6) | (modrm['reg'] << 3) | 0

                        if (operand == masked_reg) and (masked_reg in self.bin2reg[modrm['reg']]):
                            opcode_masked = True
                            if len(current_modrm) == 1:
                                values = [minreg + (x << 3) for x in range(8)]
                                current_opcodes[2] = ['{:02x}'.format(x) for x in values]
                            else:
                                current_opcodes[2] = list(set(['{:01x}?'.format(x) for x in range((modrm['mod'] << 2), (modrm['mod'] << 2) + 4)]))

                        elif (modrm['rm'] == 0b100) and (modrm['mod'] in range(0, 3)):
                            #   The instruction requires the SIB bytes
                            if len(instr['sib'][0]) == 1:
                                sib = instr['sib'][1]

                                minindex = (sib['ss'] << 6) | 0 | sib['base']
                                minbase = (sib['ss'] << 6) | (sib['index'] << 3) | 0
                                current_sib = current_opcodes[3]
                                if (sib['index'] != 0b100) and (masked_reg in self.bin2reg[sib['index']]):
                                    opcode_masked = True
                                    if len(current_sib) == 1:
                                        values = [minindex + (x << 3) for x in range(8)]
                                        current_opcodes[3] = ['{:02x}'.format(x) for x in values]
                                    else:
                                        current_opcodes[3] = list(set(['{:01x}?'.format(x) for x in range((sib['ss'] << 2), (sib['ss'] << 2) + 4)]))

                                elif masked_reg in self.bin2reg[sib['base']]:
                                    opcode_masked = True
                                    if len(current_sib) == 1:
                                        values = [minbase + x for x in range(8)]
                                        current_opcodes[3] = ['{:02x}'.format(x) for x in values]
                                    else:
                                        current_opcodes[3] = list(sorted(set(['{}?'.format(x[0]) for x in current_opcodes[3]])))

                        elif (not (modrm['rm'] == 0b100 and modrm['mod'] == 0b11)
                                and (masked_reg in self.bin2reg[modrm['rm']])):
                            opcode_masked = True
                            if len(current_modrm) == 1:
                                values = [minrm + x for x in range(8)]
                                current_opcodes[2] = ['{:02x}'.format(x) for x in values]
                            else:
                                current_opcodes[2] = list(sorted(set(['{}?'.format(x[0]) for x in current_opcodes[2]])))

                    else:
                        binreg = [x for x in self.bin2reg if masked_reg in self.bin2reg[x]][0]

                        #   Values are part of the operand
                        opcode = ord(instr['opcode'][0][-1]) - binreg
                        if ((opcode in self.reg_exceptions)
                            or ((len(instr['opcode'][0]) == 2)
                                and (opcode == self.reg_exceptions[0][1])
                                and (ord(instr['opcode'][0][0]) == self.reg_exceptions[0][0]))):
                            opcode_masked = True
                            values = range(opcode, opcode + 8)
                            if len(instr['opcode'][0]) == 2:
                                current_opcodes[1] = '{0:02x}({1})'.format(ord(instr['opcode'][0][0]),
                                                                            '|'.join(['{:02x}'.format(x) for x in values]))
                            else:
                                current_opcodes[1] = ['{:02x}'.format(x) for x in values]

                    if not opcode_masked:
                        #   Opcode couldn't be masked, revert masked disassembly
                        current_disassembly[i] = operand



        #   Register masking exceptions
        #   Instructions that leavage a base opcode value and increment it to
        #   get the right register
        #-----------------------------------------------------------------------

        #   Customize
        #   Clean up opcodes and disassembly for display to user
        current_disassembly = [x for x in current_disassembly if x]
        current_disassembly = '{0: <8}{1}'.format(current_disassembly[0], ', '.join(current_disassembly[1:]))
        opcodes = []
        for x in [x for x in current_opcodes if x]:
            if type(x) == list:
                opcodes += ['({})'.format('|'.join(x))]
            elif not re.search('(\?\?|\{.+\}|\[.+\])', x):
                opcodes += [y.encode('hex') for y in x]
            else:
                opcodes.append(x)

        return (current_disassembly, ' '.join(opcodes))

    def parse_instruction(self, ea):
        size = IDAW.DecodeInstruction(ea).size
        original = ['{:02x}'.format(IDAW.Byte(ea + i)) for i in xrange(size)]
        disassembly = IDAW.tag_remove(IDAW.generate_disasm_line(ea, 1))
        if ';' in disassembly:
            disassembly = disassembly[:disassembly.index(';')].rstrip()
        instr = {   'address': ea,
                    'bytes'  : original,
                    'disassembly' : disassembly,
                    'prefix' : ['', ],
                    'opcode' : ['', ],
                    'modr/m' : ['', ],
                    'sib'    : ['', ],
                    'disp'   : ['', ],
                    'imm'    : ['', ],
        }
        data = ''.join(original).decode('hex')

        #   Look for prefix
        prefix = ['', ]
        pre_match = re.match(self.prefixes, data)
        prefix_str = disassembly[0:disassembly.index(IDAW.GetMnem(ea))]
        if pre_match:
            prefix = [pre_match.groups()[0], prefix_str]

        elif is_64bit():
            pre_match = re.match(self.prefixes_x64, data)
            if pre_match:
                prefix = [pre_match.groups()[0], prefix_str]

        instr['prefix'] = prefix
        data = data[len(prefix[0]):]

        #   Look for opcodes
        opcodes = [data[0], IDAW.GetMnem(ea)]
        opcode = ord(opcodes[0])
        if ((opcode in self.two_opcodes)
            and (ord(data[1]) in self.two_opcodes[opcode])):
            opcodes[0] = data[0:2]
        elif ((opcode in self.three_opcodes)
            and (data[1:3] in self.three_opcodes[opcode])):
            opcodes[0] = data[0:3]
        elif ((opcode in self.two_opcodes_modrm)
            and (ord(data[1]) in self.two_opcodes_modrm[opcode])):
            opcodes[0] = data[0:2]

        instr['opcode'] = opcodes
        data = data[len(opcodes[0]):]

        #   Look for Mod R/M byte
        modrm = ['', ]
        getmodrm = False
        if (ord(opcodes[0][0]) in self.prefix_required_modrm) and (len(prefix[0]) > 0):
            getmodrm = True
        elif (ord(opcodes[0][0]) in self.prefix_required_modrm) and (len(prefix[0]) == 0):
            getmodrm = False
        elif (opcodes[0][0] == '\x01') and (len(opcodes[0]) == 1):
            getmodrm = True
        elif (ord(opcodes[0][0]) in self.noprefix_nomodrm) and (len(prefix[0]) == 0):
            getmodrm = False
        elif (len(opcodes[0]) == 1) and (ord(opcodes[0]) not in self.no_modrm):
            getmodrm = True
        elif ((len(opcodes[0]) > 1)
            and (ord(opcodes[0][0]) in self.two_opcodes_modrm)
            and (ord(opcodes[0][1]) in self.two_opcodes_modrm[ord(opcodes[0][0])])):
            getmodrm = True

        if getmodrm:
            modrm[0] = data[0]
            data = data[1:]
        instr['modr/m'] = modrm
        if len(modrm[0]) == 1:
            value = ord(modrm[0])
            mod = (value >> 6) & 3
            reg = (value >> 3) & 7  #operand 1
            rm = value & 7          #operand 2
            instr['modr/m'].append({'mod':mod, 'reg':reg, 'rm':rm})

            #   Find out the Displacement size if it has one
            #   Done for x86, 16bit would require some additional code
            displacement = 0
            if mod == 0b01:
                displacement = 8
            elif mod == 0b10:
                displacement = 32

            #   Find out if there is a SIB byte
            if (mod < 0b11) and (rm == 0b100):
                sib = data[0]
                value = ord(sib)
                ss = (value >> 6) & 3       #scale index: 2**ss
                index = (value >> 3) & 7    #register scaled: e?x * (2**ss)
                base = value & 7            #
                instr['sib'] = [sib, {'ss':ss, 'index':index, 'base':base}]
                data = data[1:]

            #   Done for x86, 16bit would require some additional code
            if displacement > 0:
                disp = data[:displacement/8]
                disp_str = '<I'
                if displacement == 8:
                    disp_str = 'B'
                instr['disp'] = [disp, hex(struct.unpack(disp_str, disp)[0])]
                data = data[displacement/8:]

        imm_map = {2 : '<H', 4 : '<I'}
        if len(data) > 0:
            if len(data) in imm_map:
                value = hex(struct.unpack(imm_map[len(data)], data)[0])
                instr['imm'] = [data, ]
            elif len(data) == 1:
                value = hex(ord(data))
            else:
                print '[Error]: immediate value is not 1, 2, or 4 bytes'

            instr['imm'] = [data, value]

        return instr

    def to_hex(self, x):
        if len(x) > 1:
            if ('{' in x and '}' in x) or (x == '??'):
                return x
        return x.encode('hex')

    def mask_operand(self, operand, to_mask, mask_value):
        if re.search(operand, to_mask):
            return re.sub(to_mask, mask_value, operand)
        else:
            return operand

#   Disassembly and Opcodes Classes
#-------------------------------------------------------------------------------
class Assembly(object):
    def __init__(self, start_ea, end_ea):
        self.original_data = []
        self.opcodes = []
        self.mnemonics = []
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.mask_options = []
        self.custom = None
        self.parser = get_parser()

        self.starts_in_function = False
        if IDAW.get_func(start_ea):
            self.starts_in_function = True

        ea = start_ea

        if (BADADDR == start_ea) or (BADADDR == end_ea):
            return

        while ea < end_ea:
            #   Check if it is in a function, if so it can be decoded without
            #   any issues arising, if not, it should be added as data bytes
            if IDAW.get_func(ea):
                instr = IDAW.DecodeInstruction(ea)
                self.original_data.append(instr)

                disassembly = IDAW.tag_remove(IDAW.generate_disasm_line(ea, 1))
                if ';' in disassembly:
                    disassembly = disassembly[:disassembly.index(';')].rstrip()

                self.mnemonics.append(disassembly)
                data = ['{0:02x}'.format(IDAW.Byte(ea + i)) for i in xrange(instr.size)]
                self.opcodes.append(' '.join(data))

                ea += instr.size

            else:
                data_byte = IDAW.Byte(ea)
                self.original_data.append(data_byte)
                self.mnemonics.append('db {0:02x}h'.format(data_byte))
                self.opcodes.append('{0:02x}'.format(data_byte))
                ea += 1

        self.original_opcodes = self.opcodes
        self.original_mnemonics = self.mnemonics

    def get_original_opcode_list(self):
        return self.original_opcodes

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

    def instruction_post_processing(self, data):
        #   TODO
        pass

    def mask_opcodes(self, mask_options):
        self.mask_options = mask_options
        if 'custom' in mask_options:
            return

        self.custom = None
        opcodes = []
        mnemonics = []

        for instr in self.original_data:
            if not isinstance(instr, insn_t):
                #   The data is just a data byte
                opcodes.append('{0:02x}'.format(instr))

            else:
                data = self.parser.mask_instruction(instr.ea, mask_options)
                if not data:
                    print '[CASC] Error: mask_instruction returned None'
                    continue

                disassembly, instr_opcodes = data
                mnemonics.append(disassembly)
                opcodes.append(instr_opcodes)

        self.mnemonics = mnemonics
        self.opcodes = opcodes

    def mask_opcodes_tuple(self, options):
        self.mask_options = options
        self.mask_opcodes(self.mask_options)

    def get_save_data_tuple(self):
        return (self.start_ea, self.end_ea, self.mask_options, self.custom)

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
    def __init__(self):
        self.mask = get_gui()

    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Assembly to Signature')
        Dialog.resize(932, 387)

        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)

        if IDA_SDK_VERSION <= 680:
            line_wrap = QtWidgets.QPlainTextEdit.LineWrapMode.NoWrap
        else:
            line_wrap = QtWidgets.QPlainTextEdit.NoWrap

        #   Original Opcodes GUI Area
        self._opcode_groupbox = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(self._opcode_groupbox.sizePolicy().hasHeightForWidth())
        self._opcode_groupbox.setSizePolicy(sizePolicy)
        self._opcode_groupbox.setFixedWidth(200)
        self._opcode_groupbox.setObjectName('_opcode_groupbox')
        self._opcode_groupbox.setTitle('Original Opcodes')
        self._opcodes = QtWidgets.QPlainTextEdit(self._opcode_groupbox)
        self._opcodes.setReadOnly(True)
        self._opcodes.setLineWrapMode(line_wrap)
        font = self._opcodes.document().defaultFont()
        font.setPointSize(12)
        font.setFamily('fixedsys,Liberation Mono')
        self._opcodes.document().setDefaultFont(font)
        self._vbox_opcodes = QtWidgets.QVBoxLayout(self._opcode_groupbox)
        self._vbox_opcodes.setContentsMargins(1, 1, 1, 1)
        self._vbox_opcodes.addWidget(self._opcodes)
        self._scrollbar_opcodes = self._opcodes.verticalScrollBar()

        #   Opcodes GUI Area
        self.opcode_groupbox = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(self.opcode_groupbox.sizePolicy().hasHeightForWidth())
        self.opcode_groupbox.setSizePolicy(sizePolicy)
        self.opcode_groupbox.setFixedWidth(200)
        self.opcode_groupbox.setObjectName('opcode_groupbox')
        self.opcode_groupbox.setTitle('Opcodes')
        self.opcodes = QtWidgets.QPlainTextEdit(self.opcode_groupbox)
        self.opcodes.setReadOnly(True)
        self.opcodes.setLineWrapMode(line_wrap)
        self.opcodes.document().setDefaultFont(font)
        self.vbox_opcodes = QtWidgets.QVBoxLayout(self.opcode_groupbox)
        self.vbox_opcodes.setContentsMargins(1, 1, 1, 1)
        self.vbox_opcodes.addWidget(self.opcodes)
        self.scrollbar_opcodes = self.opcodes.verticalScrollBar()

        #   Assembly GUI Area
        self.asm_groupbox = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(self.asm_groupbox.sizePolicy().hasHeightForWidth())
        self.asm_groupbox.setSizePolicy(sizePolicy)
        self.asm_groupbox.setObjectName('asm_groupbox')
        self.asm_groupbox.setTitle('Assembly')
        self.asm = QtWidgets.QPlainTextEdit(self.asm_groupbox)
        self.asm.setReadOnly(True)
        self.asm.setLineWrapMode(line_wrap)
        self.asm.document().setDefaultFont(font)
        self.vbox_asm = QtWidgets.QVBoxLayout(self.asm_groupbox)
        self.vbox_asm.setContentsMargins(1, 1, 1, 1)
        self.vbox_asm.addWidget(self.asm)

        #   Masking Options Area
        self.mask_options = self.mask.gui

        #   Top Horizontal Layout:  |  Opcodes | Assembly | Masking Options |
        self.hbox_top_data = QtWidgets.QHBoxLayout()
        self.hbox_top_data.setObjectName('hbox_top_data')
        self.hbox_top_data.addWidget(self._opcode_groupbox)
        self.hbox_top_data.addWidget(self.opcode_groupbox)
        self.hbox_top_data.addWidget(self.asm_groupbox)
        self.scrollbar_asm = self.asm.verticalScrollBar()
        self.hbox_top_data.addWidget(self.mask_options)

        #   Analyst's Notes Area
        self.notes = QtWidgets.QPlainTextEdit()
        self.notes.document().setDefaultFont(font)
        self.notes.setTabChangesFocus(True)
        self.notes.setFixedHeight(100)

        #   Bottom Horizontal Layout: | Error Msg | OK Button | Cancel Button |
        error_font = QtGui.QFont()
        error_font.setBold(True)
        self.error_msg = QtWidgets.QLabel('')
        self.error_msg.setFont(error_font)
        self.ok_button = QtWidgets.QPushButton('OK')
        self.ok_button.setFixedWidth(85)
        self.cancel_button = QtWidgets.QPushButton('Cancel')
        self.cancel_button.setFixedWidth(100)
        self.hbox_bottom = QtWidgets.QHBoxLayout()
        self.hbox_bottom.addWidget(self.error_msg)
        self.hbox_bottom.addWidget(self.ok_button)
        self.hbox_bottom.addWidget(self.cancel_button)

        #   Vertical Layout
        self.vbox_outer = QtWidgets.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addLayout(self.hbox_top_data)
        self.vbox_outer.addWidget(QtWidgets.QLabel('Notes:'))
        self.vbox_outer.addWidget(self.notes)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        self.ok_button.clicked.connect(Dialog.ok_button_callback)
        self.cancel_button.clicked.connect(Dialog.reject)
        self._scrollbar_opcodes.valueChanged.connect(Dialog.sync_scrolls)
        self.scrollbar_opcodes.valueChanged.connect(Dialog.sync_scrolls)
        self.scrollbar_asm.valueChanged.connect(Dialog.sync_scrolls)
        self.mask.register_signals( Dialog.apply_mask,
                                    Dialog.toggle_custom_ui)

class MiscSig_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Create Custom ClamAV Sub Signature')
        Dialog.resize(532, 287)

        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(2)

        #   ClamAV Sub Signature GUI Area
        self.sig_groupbox = QtWidgets.QGroupBox()
        sizePolicy.setHeightForWidth(self.sig_groupbox.sizePolicy().hasHeightForWidth())
        self.sig_groupbox.setSizePolicy(sizePolicy)
        self.sig_groupbox.setObjectName('sig_groupbox')
        self.sig_groupbox.setTitle('ClamAV Sub Signature')
        self.sub_signature = QtWidgets.QPlainTextEdit(self.sig_groupbox)
        font = self.sub_signature.document().defaultFont()
        font.setPointSize(12)
        font.setFamily('fixedsys')
        self.sub_signature.document().setDefaultFont(font)
        self.sub_signature.setTabChangesFocus(True)
        self.vbox_sub_signature = QtWidgets.QVBoxLayout(self.sig_groupbox)
        self.vbox_sub_signature.setContentsMargins(1, 1, 1, 1)
        self.vbox_sub_signature.addWidget(self.sub_signature)

        #   Middle Horizontal Layout:  |  Notes Label | View As Combo box |
        self.view_as_combobox = QtWidgets.QComboBox()
        self.view_as_combobox.setFixedWidth(75)
        self.hbox_middle = QtWidgets.QHBoxLayout()
        self.hbox_middle.addWidget(QtWidgets.QLabel('Notes:'))
        self.hbox_middle.addStretch(1)
        self.hbox_middle.addWidget(QtWidgets.QLabel('View As: '))
        self.hbox_middle.addWidget(self.view_as_combobox)

        #   Analyst's Notes Area
        self.notes = QtWidgets.QPlainTextEdit()
        self.notes.setTabChangesFocus(True)
        self.notes.setFixedHeight(100)
        self.notes.document().setDefaultFont(font)

        #   Bottom Horizontal Layout: | Error Msg | OK Button | Cancel Button |
        error_font = QtGui.QFont()
        error_font.setBold(True)
        self.error_msg = QtWidgets.QLabel('')
        self.error_msg.setFont(error_font)
        self.ok_button = QtWidgets.QPushButton('OK')
        self.ok_button.setFixedWidth(85)
        self.cancel_button = QtWidgets.QPushButton('Cancel')
        self.cancel_button.setFixedWidth(100)
        self.hbox_bottom = QtWidgets.QHBoxLayout()
        self.hbox_bottom.addWidget(self.error_msg)
        self.hbox_bottom.addWidget(self.ok_button)
        self.hbox_bottom.addWidget(self.cancel_button)

        #   Vertical Layout
        self.vbox_outer = QtWidgets.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addWidget(self.sig_groupbox)
        self.vbox_outer.addLayout(self.hbox_middle)
        self.vbox_outer.addWidget(self.notes)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        self.ok_button.clicked.connect(Dialog.ok_button_callback)
        self.cancel_button.clicked.connect(Dialog.reject)

class SubmitSig_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName('Dialog')
        Dialog.setWindowIcon(get_clamav_icon())
        Dialog.setWindowTitle('Submit Your ClamAV Signature')
        Dialog.resize(430, 300)

        #   Email Body Area
        self.link = QtWidgets.QLabel('')
        self.link.setTextFormat(Qt.RichText)
        self.link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.link.setOpenExternalLinks(True)
        self.email_body = QtWidgets.QPlainTextEdit()
        self.email_body.setReadOnly(True)

        #   Ok Button Area
        self.button_box = QtWidgets.QDialogButtonBox()
        self.button_box.setOrientation(Qt.Horizontal)
        self.button_box.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        self.button_box.setObjectName('button_box')
        self.hbox_bottom = QtWidgets.QHBoxLayout()
        self.hbox_bottom.addWidget(self.button_box)

        #   Vertical Layout
        self.vbox_outer = QtWidgets.QVBoxLayout(Dialog)
        self.vbox_outer.setObjectName('vbox_outer')
        self.vbox_outer.addWidget(self.link)
        self.vbox_outer.addWidget(self.email_body)
        self.vbox_outer.addLayout(self.hbox_bottom)

        #   Signal Handling
        self.button_box.accepted.connect(Dialog.accept)


#   Class to interface with Dialog GUIs and the back end data
#-------------------------------------------------------------------------------
class CASCDialog(QtWidgets.QDialog):
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
            if (BADADDR != IDAW.SelStart()) and (BADADDR != IDAW.SelEnd()):
                start_ea, end_ea = (IDAW.SelStart(), IDAW.SelEnd())

            #   Check if user has selected a basic block
            elif IDAW.get_func(IDAW.ScreenEA()):
                block = get_block(IDAW.ScreenEA())
                if None != block:
                    start_ea = block.startEA
                    end_ea = block.endEA

        if ((BADADDR != start_ea) and is_in_sample_segments(start_ea) and
            (BADADDR != end_ea) and is_in_sample_segments(end_ea - 1)):
                self.data = Assembly(start_ea, end_ea)
                self.update_opcodes_and_asm()
                self.ui._opcodes.setPlainText('\n'.join(self.data.get_original_opcode_list()))

        else:
            msg_box = QtWidgets.QMessageBox()
            msg_box.setIcon(QtWidgets.QMessageBox.Critical)
            msg_box.setWindowTitle('Cannot add Assembly to ClamAV Signature Creator')
            msg_str = ( 'Address range is not within the sample\'s '
                        'segments (0x{0:x} - 0x{1:x})')
            msg_box.setText(msg_str.format(start_ea, end_ea))
            msg_box.exec_()

            self.should_show = False

    def sync_scrolls(self, value):
        if value != self.ui._scrollbar_opcodes.value():
            self.ui._scrollbar_opcodes.setValue(value)
        if value != self.ui.scrollbar_opcodes.value():
            self.ui.scrollbar_opcodes.setValue(value)
        if value != self.ui.scrollbar_asm.value():
            self.ui.scrollbar_asm.setValue(value)

        self.old_scroll_value = value

    def set_mask(self, masking):
        self.ui.mask.set_masking(masking)

    def apply_mask(self, value):
        scroll_value = self.old_scroll_value
        self.data.mask_opcodes(self.ui.mask.get_masking())

        self.toggle_custom_ui()
        self.update_opcodes_and_asm()
        self.sync_scrolls(scroll_value)

    def toggle_custom_ui(self, is_custom=False):
        if is_custom or self.ui.mask.custom_checked():
            #   Disable selecting other mask options
            self.ui.mask.disable()

            #   Enable editing opcodes qplaintextedit
            self.ui.opcodes.setReadOnly(False)

            if is_custom:
                #   Disconnect checkbox signal to prevent reentry
                self.ui.mask.set_custom(True)
        else:
            #   Enable selecting other mask options
            self.ui.mask.enable()

            #   Disble editing opcodes qplaintextedit
            self.ui.opcodes.setReadOnly(True)

            #   Restore opcodes to match
            self.data.mask_opcodes(self.ui.mask.get_masking())
            self.update_opcodes_and_asm()

    def set_custom_opcode_list(self, opcodes):
        self.data.set_opcode_list(opcodes, True)
        self.toggle_custom_ui(True)

    def update_opcodes_and_asm(self):
        self.ui.opcodes.setPlainText('\n'.join(self.data.get_opcode_list()))
        self.ui.asm.setPlainText('\n'.join(self.data.get_mnemonics_list()))

        #   Set scroll values back to their old values
        self.ui._scrollbar_opcodes.setValue(self.old_scroll_value)
        self.ui.scrollbar_opcodes.setValue(self.old_scroll_value)
        self.ui.scrollbar_asm.setValue(self.old_scroll_value)

    def opcodes_text_changed(self):
        if self.ui.mask.custom_checked():
            self.data.set_opcode_list(self.ui.opcodes.toPlainText().split('\n'), True)

class MiscSignatureDialog(CASCDialog):
    view_as_options = ['Hex', 'ASCII', 'Unicode', 'Decoded Sig']
    msg = '<font color="#ff0000">{0} Error: {1}</font>'
    conversion_funcs = [lambda x: x.replace(' ', '').decode('hex'),
                        lambda x: unicode(x.replace(' ', '').decode('hex')),
                        lambda x: convert_to_ascii(x)]

    def __init__(self, parent, index=None, data=None, notes=None):
        super(MiscSignatureDialog, self).__init__(parent)

        self.index = index
        self.callback_fn = None
        self.conversion_error = False

        self.ui = MiscSig_Dialog()
        self.ui.setupUi(self)

        if data:
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

        elif view == self.view_as_options.index('Decoded Sig'):
            opcodes = [self.conversion_funcs[2](opcodes)]

            self.ui.sub_signature.setReadOnly(True)
            self.ui.sub_signature.setEnabled(False)

        else:
            self.ui.sub_signature.setReadOnly(False)
            self.ui.sub_signature.setEnabled(True)

        #   Set conversion error to False to prevent msg from hanging around
        if self.conversion_error:
            self.conversion_error = False
        else:
            self.ui.error_msg.setText('')

        self.ui.sub_signature.setPlainText('\n'.join(opcodes))

class SubmitSigDialog(QtWidgets.QDialog):
    def __init__(self, parent, signature, notes, breakdown):
        super(SubmitSigDialog, self).__init__(parent)

        self.callback_fn = None

        self.ui = SubmitSig_Dialog()
        self.ui.setupUi(self)

        data = ('ClamAV,\n\n'
                'I\'ve created a ClamAV Signature ({0}) with the IDA Pro '
                'ClamAV Signature Creator plugin. Please FP test and publish '
                'if it passes.\n\n'
                'Sample MD5: {1}\n\n'
                '[RESEARCH NOTES]\n\n{2}\n\n'
                '[NEW SIGNATURES]\n\n{3}\n\n'
                '[DETECTION BREAKDOWN]\n\n{4}\n\n'
                'Thanks.'
                )

        for i in xrange(len(notes)):
            if (None != notes[i][0]) and (0 < len(notes[i][0])):
                notes[i] = (' (0x{0[0]:x}, 0x{0[1]:x})'.format(notes[i][0]), notes[i][1])
            notes[i] = 'Sig{0}{1[0]}:\n{1[1]}\n'.format(i, notes[i])
        notes_str = ('\n' + '-' * 40 + '\n').join(notes)

        text = data.format(IDAW.GetInputFilePath(), IDAW.GetInputMD5(),
                            notes_str, signature, breakdown)
        self.ui.email_body.setPlainText(text)

        link_text = ('Send the below to <a href="mailto:community-sigs@lists.'
                        'clamav.net?Subject={0}&Body={1}">community-sigs@lists'
                        '.clamav.net</a>')

        data = data.format(IDAW.GetInputFilePath(), IDAW.GetInputMD5(),
                            quote_plus(notes_str), signature, breakdown)
        link_data = link_text.format('Community Signature Submission', data)
        self.ui.link.setText(link_data)


#   Model class that contains all of the sub signatures contained in this IDB
#   file. The model is initialized when the plugin is initialized from an IDC
#   array stored inside of the IDB file, so sub signatures are persistent across
#   IDA instances as long as the IDB is saved after changes are made.
#-------------------------------------------------------------------------------
class SubSignatureModel(QtCore.QAbstractTableModel):
    record_size = 1024

    def __init__(self, parent = None):
        super(SubSignatureModel, self).__init__(parent)

        self.next_index = 0
        self.index_lookup_table = []

        #   Initialize from netnodes in IDB file
        self.sigs_db = IDAW.GetArrayId('sub_signatures')
        if self.sigs_db == -1:
            self.sigs_db = IDAW.CreateArray('sub_signatures')

        self.sub_signatures = collections.OrderedDict()

        index = IDAW.GetFirstIndex(AR_LONG, self.sigs_db)
        while index != -1:
            entry = self.__get_array(index)

            self.sub_signatures[index] = entry
            self.next_index = index
            self.index_lookup_table.append(index)
            index = IDAW.GetNextIndex(AR_LONG, self.sigs_db, index)

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
            if row is None:
                return None
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
            IDAW.DelArrayElement(AR_LONG, self.sigs_db, index)
            IDAW.DeleteArray('sub_signatures_{}'.format(index))

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
        self.__set_array(element[0], notes, index)
        self.sub_signatures[index] = (element[0], notes)
        self.index_lookup_table.append(index)

    def update_sub_signature(self, sub_sig_data, notes, row_index):
        element =  sub_sig_data.get_save_data_tuple()
        index = self.index_lookup_table[row_index]

        #   Update in IDB
        self.__set_array(element, notes, index)
        self.sub_signatures[index] = (element, notes)

    def get_row_original_data(self, row_index):
        if row_index < len(self.index_lookup_table):
            return self.sub_signatures[self.index_lookup_table[row_index]]

    def __set_array(self, element, notes, index):
        array_id = 'sub_signatures_{}'.format(index)
        sig_db = IDAW.GetArrayId(array_id)
        if sig_db == -1:
            sig_db = IDAW.CreateArray(array_id)

        data = pickle.dumps((element, notes))

        begin = 0
        for i in xrange(0, int(math.ceil(float(len(data)) / self.record_size))):
            begin = i * self.record_size
            end = begin + self.record_size
            IDAW.SetArrayString(sig_db, i, str(data[begin:end]))

        IDAW.SetArrayLong(IDAW.GetArrayId('sub_signatures'), index, 1)

    def __get_array(self, index):
        sig_db = IDAW.GetArrayId('sub_signatures_{}'.format(index))
        if sig_db == -1:
            return None

        data = ''
        index = 0
        while index != -1:
            data += IDAW.GetArrayElement(AR_STR, sig_db, index)
            index = IDAW.GetNextIndex(AR_STR, sig_db, index)

        element, notes = pickle.loads(data)
        return (element, notes)


#   Main Plug-in Form Class
#-------------------------------------------------------------------------------
class SignatureCreatorFormClass(PluginForm):
    system = {0 : 'Unknown', 1 : 'Win', 6 : 'Linux', 9 : 'Osx'}

    def __init__(self):
        super(SignatureCreatorFormClass, self).__init__()

    def OnCreate(self, form):
        global add_sig_handler_in_menu

        self.form = form

        #   For compatability with IDA 6.8 and lower
        try:
            self.parent = self.FormToPySideWidget(form)
        except AttributeError:
            self.parent = self.FormToPyQtWidget(form)

        self.populate_model()
        self.populate_main_form()

        system = self.system[get_file_type()]
        self.sample_name.setText('{0}.Trojan.Agent'.format(system))

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
            QtWidgets.QApplication.clipboard().setText(to_copy)

    def insert_asm_item(self, ctx=None):
        self.Show('ClamAV Signature Creator')
        dialog = AsmSignatureDialog(self.parent)
        dialog.registerSuccessCallback(self.sub_signature_model.add_sub_signature)
        dialog.setModal(True)
        dialog.show()

    def insert_string_item(self, ctx):
        #   Get IDA's toplevel chooser widget
        #   For compatability with IDA 6.8 and lower
        try:
            chooser = self.FormToPySideWidget(ctx.form)
        except AttributeError:
            chooser = self.FormToPyQtWidget(ctx.form)

        #   Get the embedded table view
        table_view = chooser.findChild(QtWidgets.QTableView)
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

        sub_signature = [data[x] for x in sorted(data.keys())]
        try:
            notes = [x.replace(' ', '').decode('hex') for x in sub_signature]
            notes = map(unicode, notes)
        except UnicodeDecodeError:
            pass

        self.insert_custom_item(' * '.join(sub_signature), '\n'.join(notes))

    def insert_import_item(self, ctx):
        try:
            chooser = self.FormToPySideWidget(ctx.form)
        except AttributeError:
            chooser = self.FormToPyQtWidget(ctx.form)

        #   Get the embedded table view
        table_view = chooser.findChild(QtWidgets.QTableView)
        sort_order = table_view.horizontalHeader().sortIndicatorOrder()
        sort_column = table_view.horizontalHeader().sortIndicatorSection()

        #   Get the table view's data
        model = table_view.model()
        sel = ctx.chooser_selection

        data = {}
        for row_data in table_view.selectionModel().selectedRows():
            index = row_data.row()

            address = int(model.data(model.index(index, 0), Qt.DisplayRole), 16)
            name = model.data(model.index(index, 2), Qt.DisplayRole)

            data[address] = ' '.join([x.encode('hex') for x in name]) + ' 00'

        sub_signature = [data[x] for x in sorted(data.keys())]
        try:
            notes = [x.replace(' ', '').decode('hex') for x in sub_signature]
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
        filename = QtWidgets.QFileDialog.getSaveFileName(self.parent, 'Save CSV export to...')
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
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        tableview = QtWidgets.QTableView()
        tableview.setModel(self.sub_signature_model)
        tableview.setSortingEnabled(False)
        tableview.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        tableview.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
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
        copy_action = QtWidgets.QAction('&Copy', self.parent)
        copy_action.setShortcut('Ctrl+C')
        insert_action = QtWidgets.QAction('&Insert', self.parent)
        insert_action.setShortcut('Ins')
        insert_assembly_action = QtWidgets.QAction('&Insert Assembly', self.parent)
        insert_assembly_action.setShortcut('Ctrl+Ins')
        export_action = QtWidgets.QAction('E&xport all to CSV...', self.parent)
        export_action.setShortcut('Shift+Ins')
        delete_action = QtWidgets.QAction('&Delete', self.parent)
        delete_action.setShortcut('Del')
        separator = QtWidgets.QAction(self.parent)
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
        generate_button = QtWidgets.QPushButton('Create ClamAV Signature')
        generate_button.setFixedWidth(160)
        generate_button.clicked.connect(self.generate_signature)
        sample_name_label = QtWidgets.QLabel('Name:')
        self.sample_name = QtWidgets.QLineEdit()
        self.sample_name.setFixedHeight(generate_button.sizeHint().height())
        hboxview = QtWidgets.QHBoxLayout()
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
                dialog = MiscSignatureDialog(self.parent, index=row_index)

            if None != custom_opcodes:
                dialog.set_custom_opcode_list(custom_opcodes)

            dialog.ui.notes.setPlainText(notes)
            dialog.update_opcodes_and_asm()
            dialog.registerSuccessCallback(self.sub_signature_model.update_sub_signature)
            dialog.setModal(True)
            dialog.show()

    def generate_signature(self):
        ndb_format = '{0}:{1}:*:{2}:70'
        ldb_format = '{0};Engine:70-255,Target:{1};{2};{3}'

        msg_box = QtWidgets.QMessageBox()
        msg_box.setIcon(QtWidgets.QMessageBox.Critical)
        msg_box.setWindowTitle('Unable to create ClamAV Signature')

        #   Ensure the signature name is valid
        name = self.sample_name.text()
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
        breakdown = {'name' : 'VIRUS NAME: {}'.format(name),
                    'description' : 'TDB: Engine:51-255,Target:{0}'.format(file_type),
                    'subsigs' : {}}
        sig_id = 0
        for (start_ea, end_ea, mask_options, custom_opcodes), note in sub_sigs:
            temp_note = ('', note)
            breakdown['subsigs'][sig_id] = {'offset' : 'OFFSET: ANY',
                                            'sigmod' : 'SIGMOD: NONE',
                                            'subsig' : convert_to_ascii(custom_opcodes)}
            if (None != start_ea) and (None != end_ea):
                obj = Assembly(start_ea, end_ea)
                obj.mask_opcodes_tuple(mask_options)
                temp_note = ((start_ea, end_ea), note)
                breakdown['subsigs'][sig_id]['subsig'] = '\n'.join(obj.get_mnemonics_list())

                if None == custom_opcodes:
                    custom_opcodes = obj.get_opcode_list()
                else:
                    temp = '{0}\n{1}\n{0}'.format(  '{0}CUSTOMIZE SUBSIG FROM{0}'.format('*'*20),
                                                    breakdown['subsigs'][sig_id]['subsig'])
                    breakdown['subsigs'][sig_id]['subsig'] = temp

            elif None == custom_opcodes:
                msg_box.setText(('Saved data is incorrectly formated.\nCould '
                                'not retrieve sub signatures data.'))
                msg_box.exec_()
                continue

            opcodes.append(''.join(custom_opcodes).replace(' ', ''))
            notes.append(temp_note)
            sig_id += 1

        #   Create signature based on opcodes
        if 0 == len(opcodes):
            msg_box.setText('No opcodes to create a sig with')
            return msg_box.exec_()

        elif 1 == len(opcodes):
            #   Create NDB signature
            signature = ndb_format.format(name, file_type, ''.join(opcodes[0]).replace('', ''))
            breakdown['description'] = 'TARGET TYPE: {}'.format(get_type_name(file_type))
            format_str = (  '{0[offset]}\n'
                            'DECODED SUBSIGNATURE:\n{0[subsig]}')
            breakdown['breakdown'] = format_str.format(breakdown['subsigs'][0])
            breakdown['decoded'] = '{0[name]}\n{0[description]}\n{0[breakdown]}'.format(breakdown)
            print 'NDB created from custom_opcodes:\n\t{0}\n'.format(signature)

        else:
            format_str = (  ' * SUBSIG ID {0}\n'
                            ' +-> {1[offset]}\n'
                            ' +-> {1[sigmod]}\n'
                            ' +-> DECODED SUBSIGNATURE:\n{1[subsig]}')
            #   Create LDB signature
            condition = '&'.join(map(str, range(len(sub_sigs))))
            signature = ldb_format.format(name, file_type, condition, ';'.join(opcodes))
            breakdown['logical'] = 'LOGICAL EXPRESSION: {}'.format(condition)
            indexes = sorted(breakdown['subsigs'].keys())
            breakdowns = [format_str.format(i, breakdown['subsigs'][i]) for i in indexes]
            breakdown['breakdown'] = '\n'.join(breakdowns)
            breakdown['decoded'] = '{0[name]}\n{0[description]}\n{0[logical]}\n{0[breakdown]}'.format(breakdown)
            print 'LDB created from custom_opcodes:\n\t{0}\n'.format(signature)

        print breakdown['decoded']

        #   Display dialog to user
        dialog = SubmitSigDialog(self.parent, signature, notes, breakdown['decoded'])
        dialog.setModal(True)
        dialog.show()

        return signature

    def OnClose(self,form):
        pass


#   ClamAV Signature Creator (CASC) Plug-in Class
#-------------------------------------------------------------------------------
class ClamAVSigCreatorPlugin(plugin_t):
    flags = IDAW.PLUGIN_FIX
    comment = 'Aids analysts in creating ClamAV NDB and LDB signatures'

    #   IDA Pro display details
    help = 'Creates ClamAV signatures from selected data from an IDB'
    wanted_name = 'ClamAV Signature Creator'
    wanted_hotkey = '`'

    def init(self):
        global clamav_sig_creator_plugin

        file_type = IDAW.GetCharPrm(INF_FILETYPE)

        #   Currently only supports intel_x86
        if get_file_type() not in [1, 6, 9]:
            msg_str = '{0} does not support this file type.\n'
            msg(msg_str.format(self.wanted_name))
            return PLUGIN_SKIP

        #   Check to see if we've configured the plug-in yet.
        if not clamav_sig_creator_plugin:
            clamav_sig_creator_plugin = SignatureCreatorFormClass()

        return IDAW.PLUGIN_OK

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
