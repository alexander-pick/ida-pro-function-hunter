#
#   IDA Pro Function Hunter
#   released unter MIT license, see Readme.md for details
#   2019-2024 by Alexander Pick
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
import json

danger = None
call_refs = None
pure_terror = None

script_dir = os.path.dirname(os.path.realpath(__file__))+"/"

def update_toml():
    
    global script_dir
    update_url = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

    try:

        response = requests.get(update_url)

        if response.ok:
            with open(script_dir+"gitleaks.toml", mode="wb") as file:
                file.write(response.content)
        else:
            raise
            
    except:
        print("[e] error downloading update toml file!")
        pass

    return True

def write_log(log_line):
    current_text = get_ida_notepad_text()
    
    future_text = ""
    
    if(current_text):
        future_text += str(current_text)
    
    future_text += (log_line + "\n")

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
    #seg_start = get_segm_start(addr)
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
    
    if(not xrefs):
        print("[i] xref: no xrefs to %x" % addr)
        return

    # iterate over each cross-reference
    for xref in xrefs:
        #print("xref: %x" % xref)
        opcode = print_insn_mnem(xref).lower()

        if(is_call(opcode)):
            #print("[d] xref: found call to %s (%x) at %x" % (name, addr, xref))

            if(is_ins_segment_stub(xref)):

                current_func = get_func_name(xref)
                # print("[d] %s is a stub func at %x, digging deeper" %
                #       (current_func, xref))

                # get startEA
                func = get_func(xref)
                # evil recurision, need to go deeper in the dungeon
                get_call_xrefs(func.start_ea, name)

            else:

                if(is_ins_seg_executable(xref)):

                    # print("call is in a executable segment")
                    mark_and_bp(xref, name)

                else:

                    #print("[d] found %x but seems to be a ref, digging deeper" % xref)
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
        print("[e] import_callback(): %s" % e)

    return True

def regex_search(regex_patterns, supicious_strings):

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
                #print("[d] %s: %s" % (item[1], item[0]))
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

    except Exception as e:
        print("[e] string analysis error: %s" % e)
        pass

    return True

def run():
    
    global script_dir
    
    with open(script_dir+"/config.json") as fh_config:
        
        fh_config = json.load(fh_config)
        
        global call_refs
        call_refs = fh_config["call_refs"]
        
        global pure_terror
        pure_terror = fh_config["pure_terror"]
        
        global danger
        danger = fh_config["insecure_funcs"] + fh_config["insecure_rands"] + fh_config["pure_terror"]

        print("--> IDA Function Hunter")

        print("[i] running search for dangerous functions")

        print("[i] checking imports")

        for val in range(0, get_import_module_qty()):
            name = get_import_module_name(val)
            enum_import_names(val, import_callback)
            # try:
            #    name = get_import_module_name(val)
            #    enum_import_names(val, import_callback)
            # except Exception as e:
            #    print("An error occured!")
            #    print(e)

        print("[i] checking embedded functions")

        for addr in Functions():
            for item in danger:
                if item in get_func_name(addr).lower():
                    if(len(name) < (len(item) + 4)):
                        print("[i] function: found %s at %x" % (name, addr))
                        get_call_xrefs(addr, name)

        print("[i] updating string signatures")

        update_toml()

        print("[i] running string analysis")

        regex_search(fh_config["regex_patterns"], fh_config["supicious_strings"])

        print("[i] done")

run()

if(len(idc.ARGV)):
    if(idc.ARGV[1] == "batchjob"):
        idc.qexit(0)