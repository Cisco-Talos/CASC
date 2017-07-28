## ClamAV Signature Creator (CASC) - IDA Pro plug-in to generate signatures



## Disclaimer

THE SOFTWARE TOOL AND RELAED DATA (THE “TOOL”) AND ANY ALTERATIONS, MODIFICATIONS, ENHANCEMENTS AND IMPROVEMENTS THERETO AND TECHNICAL SUPPORT (IF ANY) ARE BEING PROVIDED TO YOU ON AN “AS-IS” BASIS, WITHOUT WARRANTY, EXPRESS OR IMPLIED, OF ANY KIND INCLUDING, BUT NOT LIMITED TO, ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK ARISING OUT OF YOUR USE OF THE TOOL REMAINS SOLELY WITH YOU. YOU ACKNOWLEDGE AND AGREE THAT USE OF THE TOOL IS SOLELY AT YOUR OWN RISK. IN NO EVENT SHALL CISCO OR ITS LICENSORS BE LIABLE FOR ANY DIRECT OR INDIRECT DAMAGES WHATSOEVER AS A RESULT OF YOUR USE OF THE TOOL, INCLUDING, WITHOUT LIMITATION, LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF DATA, OR OTHER LOSS ARISING OUT OF THE USE OF OR INABILITY TO USE THE TOOL, EVEN IF CISCO HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, OR FOR ANY CLAIM BY YOU OR BASED ON A THIRD PARTY CLAIM.



## CASC
The ClamAV Signature Creator (CASC), is an IDA Pro plug-in to aid reverse 
engineers in creating ClamAV NDB and LDB signatures from IDA Pro's Disassembly 
or Strings view.

CASC should run on any platform that supports IDA Pro 6.7 and higher.
Limited functionality is available for IDA Pro 6.6.
The signature analyzer part of CASC has only been tested on IDA 6.9.

README with pictures can be found on our wiki:
    [https://github.com/vrtadmin/casc/wiki](https://github.com/vrtadmin/casc/wiki)

## Building
You need a working build system to build the yara-python library. On Ubuntu,
you can get that by installing `sudo apt-get install -y build-essential
libpython2.7-dev:i386 gcc-multilib`.

Run `python package.py --output <output-dir>` to build the plugin zip archives.

## Installation

The ClamAV Signature Creator (CASC) is easy to install. You simply have to
unzip one of the generated zip archives into the IDA Pro installation directory
(not inside _plugins_ directory, but the one where _idaq_ is located). Which
archive you may want to use depends on your python configuration. If you use
the system's python, choose the _casc-\*-universal.zip_ package, and then
install the packages _ply_ and _yara_ via _pip_ or your system packages (When you
install _yara_ via _pip_, you need to take great care to have pip build 32 bit
libraries. Do that by exporting the environment variables _CFLAGS=-m32_
_CXXFLAGS=-m32_ _LDFLAGS=-m32_ before you invoke pip).

If you are using IDA's bundled python, you can choose one of the
_casc-\*-fat.zip_ archives, depending on your operating system. They have all
the libraries bundled which you would otherwise install with pip. 

In case you don't want to install additional libraries, the plugin will degrade
gracefully and hide the _"Analyze"_ functionality which requires the libraries to
be installed.

| Operating System               | IDA Pro Plug-in Path                     |
| ------------------------------ | -----------------------------------------|
| Windows XP (x86)               | `C:\Program Files\IDA 6.7\plugins\`        |
| Windows Vista and higher (x64) | `C:\Program Files (x86)\IDA 6.7\plugins\`  |
| Linux                          | `<ida_install_dir>/plug-ins `              |

## Support Information

ClamAV Signature Creator (CASC) is meant for creating ClamAV signatures on the
sample as it exists on disk. Sub signatures could be based off unpacked code
during the sample’s execution, however, ClamAV would not be able to match those
signatures (some exception exist for automatic unpackers built into ClamAV).

Tested on
---------
| IDA Pro Version | OK | Notes                                              |
| ----- | --------------- | ---------------------------------------------------|
| 6.7 | Y            |                                                    |
| 6.6 | Y            | Doesn't support right click option in IDA View or Strings Windows |
| 6.5 | N            | IDA doesn't provide PySide and Qt support          |
 
File Types
----------
| Architecture  | Type      | OK |
| ----- | ------------- | --------- |
| Intel x86/x64 | PE, .NET  | Y |
| Intel x86/x64 | ELF       | Y |
| Intel x86/x64 | OSX       | Y |

Opening Plug-in
===============
Once the Python script is copied to the IDA Pro plug-ins folder, open IDA Pro 
with a sample. There are two ways of opening the plug-in.

 -  IDA Pro’s Plug-in Menu (Edit -> Plugins -> ClamAV Signature Creator
 -  Press \` (backtick)

Once the plug-in is opened you will be able to view sub signatures created in 
the past and saved in the IDB, add new misc ClamAV sub signatures, and add sub 
signatures generated from disassembly selected in the IDB.

## Creating Sub Signatures

Sub signatures can either be created from disassembly viewable from within IDA 
Pro or manually from entering/creating a valid ClamAV sub signature.

### Insert Misc. Sub Signature

A custom ClamAV sub signature can be created in a couple of different ways:
 -  Within the CASC plug-in window, press the Ins key
 -  Within the CASC plug-in window, right click and select "Insert"
 -  Within the Strings window; select the string(s) of interest, right click, 
    and select "Add string to ClamAV Signature Creator"

### Insert Assembly Sub Signature

There are several ways to create a sub signature from disassembly within the 
IDB. All methods involve first selecting the code you are interested in 
creating a signature from. Either highlight the code or position and click your 
cursor in the basic block of interest, then:

- Within the CASC plug-in window, press Ctrl+Ins
- Within the CASC plug-in window, right click and select "Insert Assembly"
 -  Within the IDA View window by
     *  Pressing Ctrl+\`
     *  Right click and select "Add Assembly to ClamAV Sig Creator…"

The Assembly to Signature window will allow you to insert notes for the sub 
signature, apply various masking options, and scroll through the 
opcodes/assembly associated with that sub signature.

Selecting a masking option will change the opcodes and assembly text if the 
masking option can be applied. Selecting "Customize" will allow you to edit the
opcodes (note the assembly area will not update for any customizations made). 
If you uncheck “Customize” then all previously applied masking options will be 
applied and the customizations will be deleted.

## Common Problems
If a masking option is selected but the opcodes and assembly don’t change:

	ESP Offsets
        This will apply to [esp+offset] operands only
	EBP Offsets
        This will apply to [ebp+offset] operands only

### Absolute Calls
IDA might display the disassembly as 
    
`call      memset`

However, that instruction may be a call to a function within the sample 
    that directly calls or jumps to the actual memset function. If that is the 
    case, no changes will be made.
Global Offsets
	Still in testing, report any issues to  
    [https://github.com/vrtadmin/casc/issues](https://github.com/vrtadmin/casc/issues)

### Editing Sub Signatures

To edit a signature, simply double click on the signature within the CASC 
plug-in window and the signature will open up for editing. Any changes made 
will be saved only if you press OK. Prior to saving a sub signature it will 
undergo a verification to ensure it correctly conforms to a ClamAV signature 
component. If any problems exist, clicking the OK but will result in an error 
message to its right. The error must be corrected before the sub signature will
be saved.

## Creating ClamAV Signature

Before creating a signature, make sure to give it a descriptive ClamAV 
signature name (the default is Win.Trojan.Agent). Once a sub signature(s) is 
created, you can select one or more sub signatures from the CASC plug-in window
(use Ctrl or Shift keys to select multiple signatures) and click the 
"Create ClamAV Signature"

Once the “Create ClamAV Signature” button is click a dialog box with a 
formatted email will be displayed for the user to send to ClamAV’s 
community-sigs list. Selecting the [community-sigs@lists.clamav.net](community-sigs@lists.clamav.net) hyperlink  is a mailto: link. It will attempt to copy the signature information displayed  to the systems default mail client. Keep in mind if any special characters are  used then the email’s contents may not be correct and will need to be manually  copied over.

## Analyzing ClamAV signatures
In the main plugin panel, use the tabbed pane to switch to the _"Analyze"_
mode. Note that this tab is not available if you don't have the required
libraries installed.  You can now paste a ClamAV .ldb or .ndb signature in the
text field above the _"Add Signature"_ button. Once you then click _Add
signature_, the signature will appear in the left top list (if it was well
formatted and parsed by the plugin, otherwise check the IDA Pro output window
for errors). Now you can double-click on the signature in the list. For .ndb
signatures this will directly bring you to the matched part of the binary,
and color the match in red. For .ldb signatures, the subsignatures will be
displayed in the right list element. If you double-click any of the sub
signature entries, it will bring you to the match for this subsignature.

## Bugs and Support
There is no support provided with CASC. 

If you think you've found a bug, please report it at:
[https://github.com/vrtadmin/casc/issues](https://github.com/vrtadmin/casc/issues)

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

 -  The version of IDA Pro you're using
 -  The operating system used to run IDA Pro
 -  Any CASC related errors printed out in IDA Pro's output window
 -  Task trying to accomplish
 -  Any other relevant information

Other options for communication can be found at:
    [https://github.com/vrtadmin/casc/wiki](https://github.com/vrtadmin/casc/wiki)
