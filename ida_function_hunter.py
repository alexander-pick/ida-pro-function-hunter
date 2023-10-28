#
#   IDA Pro Function Hunter
#   released unter MIT license, see Readme.md for details
#   2019-2023 by Alexander Pick
#

from idautils import *
from idaapi import *
from idc import *
from ida_nalt import *
from ida_funcs import *
from ida_bytes import *

import re
import tomli
import requests
import os

# all kind of imports which need review
# https://dwheeler.com/secure-programs/Secure-Programs-HOWTO/dangers-c.html

insecure_funcs = ['gets', 'getwd', 'malloc', 'memcmp', 'memcpy', 'memmove', 'me​mset', 'scanf', 'sprintf​', 'fscanf', 'sscanf', 'stpcpy',
                  'strcat', 'strcpy', 'strlen', 'strtok', 'strtok_r', 'swprintf', 'swscanf', 'vscanf', 'vsnprintf', 'vfscanf',
                  'vsprintf', 'vsscanf', 'vswprintf', 'wcpcpy', 'wcpncpy', 'wcrtomb', 'wcscat', 'wcscpy', 'wcslen', 'wcsncat', 'wcsncpy',
                  'wcsnrtombs', 'wcsrtombs', 'wcstok', 'wcstombs', 'wctomb', 'wmemcmp', 'wmemcpy', 'wmemmove', 'wmemset', 'wscanf',
                  '​alloca', '​realpath', 'popen', 'strcmp', 'sprintf', 'atoi', 'atoll', 'atof', 'calloc', 'alloc', 'realloc', 'free', 'strcasecmp',
                  'getpass', 'getopt', 'streadd', 'strecpy', 'strtrns', 'getwd']

insecure_rands = ["drand48", "erand48", "jrand48", "lcong48", "random",
                  "lrand48", "mrand48", "nrand48", "rand", "seed48", "srand", "srand48", "_arc4random", "_arc4random_uniform", "_swift_stdlib_random"]

# https://codewithchris.com/swift-random-number/

pure_terror = ['system', 'exec', 'execve', 'execl',
               'execle', 'execlp', 'exect', 'execv', 'execvp', "ptrace"]

danger = insecure_funcs + insecure_rands + pure_terror

# TODO: opcodes
opcodes = ["rdtsc", "xor"]

# search and report interesting strings
supicious_strings = ["PRIVATE KEY"]

# review patterns (URLs, keys)
regex_patterns = [
                  # URLs
                  [ r'^/(?!xml)(://[\da-z./?A-Z0-9\D=_-]*)$', "Url" ],
                  # Google API Key
                  [ r'AIza[0-9A-Za-z-_]{35}', 'Google API Key' ],
                  # basic auth
                  [ r'^(\"|\')?Basic [A-Za-z0-9\\+=]{60}(\"|\')?$', 'basic auth' ],
                  # bearer token
                  [ r'earer\s[\d|a-f]{8}-([\d|a-f]{4}-){3}[\d|a-f]{12}', "bearer token" ],
                  # AWS secrets
                  [ r"^[0-9a-zA-Z/+]{40}$", "AWS secrets" ],
                  # Base64
                  [ r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', 'Base64' ],
                  # HTTP Auth Credentials
                  [ r'://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+', 'HTTP Auth Credentials' ],
                  # ipv4
                  [ r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b', 'ipv4' ],
                  # ipv6
                  [ r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))', 'ipv6' ],
                  # MD5 Hash
                  [ r'[a-f0-9]{32}', 'MD5 Hash' ],
                  ]

# call References, needed for analysis
call_refs = ["call", "bl", "br", "beq", "b", "blx", "bx"]

script_dir = os.path.dirname(os.path.realpath(__file__))+"/"

def update_toml():
    global script_dir
    update_url = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

    response = requests.get(update_url)

    if response.ok:
        with open(script_dir+"gitleaks.toml", mode="wb") as file:
            file.write(response.content)
    else:
        print("[e] error downloading update toml file!")

    return True

def write_log(log_line):
    current_text = get_ida_notepad_text()
    future_text = (str(current_text) + log_line + "\n")

    set_ida_notepad_text(future_text, len(future_text))

    print("[i] " + log_line)

# gets the segment  and checks if it's an executable one
def is_ins_seg_executable(addr):
    segment = getseg(addr)
    segment.perm
    if (not segment) or (segment.perm & SEGPERM_EXEC) == 0:
        return False
    else:
        return True

# this is mainly for macho/swift code, look if it's a stub in a stub segment
def is_ins_segment_stub(addr):
    seg_start = get_segm_start(addr)
    seg_name = get_segm_name(addr)
    # print("%x: %s" % (seg_start, seg_name))
    if "stub" in seg_name:
        return True
    else:
        return False


def is_call(opcode):
    for item in call_refs:
        if (item) in opcode:
            return True

    return False


def mark_and_bp(addr, name):
    # set breakpoint
    add_bpt(addr, 0, BPT_SOFT)

    # disable it for later review by default
    disable_bpt(addr)

    # unless it's pure evil
    for item in pure_terror:
        if (item) in name:
            enable_bpt(addr)

    # set a comment for the bp what it refs to
    set_cmt(addr, ("usage of %s" % name), 0)

    # colorize function
    #func = get_func(addr)
    #set_color(func.start_ea, CIC_ITEM, 0xcdffff)


def get_call_xrefs(addr, name):

    xrefs = CodeRefsTo(addr, False)

    # iterate over each cross-reference
    for xref in xrefs:
        #print("xref: %x" % xref)
        opcode = print_insn_mnem(xref).lower()

        if is_call(opcode):
            print("[-] xref: found call to %s (%x) at %x" % (name, addr, xref))

            if is_ins_segment_stub(xref):

                current_func = get_func_name(xref)
                print("[-] %s is a stub func at %x, digging deeper" %
                      (current_func, xref))

                # get startEA
                func = get_func(xref)
                # evil recurision, need to go deeper in the dungeon
                get_call_xrefs(func.start_ea, name)

            else:

                if is_ins_seg_executable(xref):

                    # print("call is in a executable segment")
                    mark_and_bp(xref, name)

                else:

                    print("[-] found %x but seems to be a ref, digging deeper" % xref)
                    # evil recurision
                    get_call_xrefs(xref, name)


def import_callback(addr, name, ord):

    global danger

    try:
        for item in danger:

            if (item) in name:

                # avoid false positives in super long func names, i.e. objc
                if len(name) < (len(item) + 4):
                    print("[i] import: found %s at %x" % (name, addr))
                    get_call_xrefs(addr, name)

    except Exception as e:
        print(e)

    return True

def regex_search():

    global regex_patterns
    global supicious_strings

    try:
        #load here or IDA will explode if done in the loop :)
        f = open(script_dir+"gitleaks.toml", "rb")
        gl_data = tomli.load(f)

        for s in Strings():
            #print(s.ea, s.length, s.strtype)

            # get String and process it
            idastring = get_strlit_contents(s.ea, -1, -1)

            # search simple string match
            for item in supicious_strings:
                if item in str(idastring):
                    write_log("suspicious string (%s) at %x" % (idastring, s.ea))

            # search regex
            for item in regex_patterns:
                #print(item[1])
                match = re.search(item[0], str(idastring))
                if match:
                    #avoid stupid matches like "::" with ipv6
                    if(len(match.group(0)) > 3):
                        write_log("found regex match %s at %x (%s)" % (match.group(0), s.ea, item[1]))

            
            # more regex, key regex file borrowed from gitleaks
            # https://raw.githubusercontent.com/zricethezav/gitleaks/master/config/gitleaks.toml


            for gl_item in gl_data["rules"]:
                #print(gl_item["description"])
                try:
                    match = re.match(gl_item["regex"], str(idastring))
                    if match:
                        write_log("found gl-regex match %s at %x (%s)" % (match.group(0), s.ea, gl_item["description"]))
                except Exception as e:
                    # disabled due to too many regex warnings
                    #print("[e] problem with regex %s: %s" % (gl_item["regex"], str(e)))
                    pass

    except:
        print("[e] string analysis failed")
        pass

    return True

def run():

    global danger

    print("--> IDA Function Hunter")

    print("[i] running search for dangerous functions")

    print("[s] checking imports")

    for val in range(0, get_import_module_qty()):
        name = get_import_module_name(val)
        enum_import_names(val, import_callback)
        # try:
        #    name = get_import_module_name(val)
        #    enum_import_names(val, import_callback)
        # except Exception as e:
        #    print("An error occured!")
        #    print(e)

    print("[s] checking embedded functions")

    for addr in Functions():
        for item in danger:
            if item in get_func_name(addr).lower():
                if len(name) < (len(item) + 4):
                    print("[i] function: found %s at %x" % (name, addr))
                    get_call_xrefs(addr, name)

    print("[s] updating string signatures")

    update_toml()

    print("[s] running string analysis")

    regex_search()

    print("[i] function hunter has finished")

run()