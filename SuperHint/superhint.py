import os
import idc
import json
import idaapi
import ida_idp
import ida_idaapi
import ida_hexrays
import ida_kernwin
import ctypes


struct_counter = 0
struct_db = {"struct_counter": 0}


def edit_hint(cmt):
    return ida_kernwin.ask_text(1000, cmt, "Edit hint")

def set_strct_hints(udm_info, parent_type):
    print(f"udm name: {udm_info.name}")

def set_lvar_hints(lvar, nw_hint):
    lvar.cmt = nw_hint

def hotkey_pressed():
    global struct_db, struct_counter
    print("[+] Edit Hint")

    viewer = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(viewer) != ida_kernwin.BWN_PSEUDOCODE:
        print("[!] Not in pesudocode")
        return

    
    vu = idaapi.get_widget_vdui(viewer)
    if vu.get_current_item(idaapi.USE_MOUSE):
            item = vu.item
    else:
        return

    lvar = item.get_lvar()
    if(lvar):
        new_hint = edit_hint(lvar.cmt)
        if(new_hint == None):
            new_hint = lvar.cmt
        
        set_lvar_hints(lvar, new_hint)
        return
    
    udm_info = idaapi.udm_t()
    struct_info = idaapi.tinfo_t()
    member_idx = item.get_udm(udm_info, struct_info)
    if(member_idx != -1):
        struct_id = struct_info.get_type_cmt()

        if(struct_id == None):
            struct_id = "struct" + str(struct_counter)
            struct_db[struct_id] = {}
            struct_info.set_type_cmt(struct_id)
            struct_counter += 1
            struct_id = struct_info.get_type_cmt()


        member_offset = str(udm_info.offset)
        if member_offset not in struct_db[struct_id]:
            struct_db[struct_id][member_offset] = ""


        target_struct = struct_db[struct_id]
        new_hint = edit_hint(target_struct[member_offset])

        if(new_hint == None):
            new_hint = target_struct[member_offset]

        target_struct[member_offset] = new_hint    
        return


class hint_hooks(ida_hexrays.Hexrays_Hooks):
    global struct_db
    def create_hint(self, vu):
        if vu.get_current_item(idaapi.USE_MOUSE):
                item = vu.item

        lvar = item.get_lvar()
        if(lvar):
            return 5, lvar.cmt, 1000
        
        udm_info = idaapi.udm_t()
        struct_info = idaapi.tinfo_t()
        member_idx = item.get_udm(udm_info, struct_info)
        if(member_idx != -1):
            struct_id = struct_info.get_type_cmt() 
            #print(struct_id)
            #print(struct_db)

            member_offset = str(udm_info.offset)
            if(struct_id == None or member_offset not in struct_db[struct_id]): 
                return 0
    
            target_struct = struct_db[struct_id]
            return 5, target_struct[member_offset], 1000

        return 0


class MyPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.init_state = 0
        self.filename = idc.get_root_filename()
        self.jsonname = idc.get_root_filename() +  "_db.json"
        self.osw_hint_hook = None


    def __del__(self):
        print("what the fuck is happening")
        self.remove_hint_hook()
        self.struct_db_store()

    def struct_db_init(self):
        global struct_db, struct_counter

        if os.path.exists(self.jsonname):
            with open(self.jsonname, 'r', encoding='utf-8') as f:
                struct_db = json.load(f)
                struct_counter = struct_db["struct_counter"]
        else:
            struct_counter = 0
            struct_db = {"struct_counter": 0}

        #print(struct_db)

    def struct_db_store(self):
        global struct_db, struct_counter

        struct_db["struct_counter"] = struct_counter
        with open(self.jsonname, 'w', encoding='utf-8') as f:
            json.dump(struct_db, f)


    def install_hint_hook(self):

        if not ida_hexrays.init_hexrays_plugin():
            print("[-] Hex-Rays Decompiler is not loaded.")
        else:
             print("[+] Hex-Rays Decompiler is loaded.")


        self.remove_hint_hook()

        self.osw_hint_hook = hint_hooks()
        if self.osw_hint_hook.hook() == 0:
            print("[!] hint_hooks Error")

        print("[+] hint hook done")


    def remove_hint_hook(self):
        if self.osw_hint_hook:
            self.osw_hint_hook.unhook()
            self.osw_hint_hook = None

    def run(self, arg):        
        print("[+] run called")

        if(self.osw_hint_hook == None):
            self.install_hint_hook()
            self.struct_db_init()
        else:
            hotkey_pressed()
        

class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_KEEP
    comment = "plugin for editing hints"
    help = "add/edit comments to hints. Supports local variable and structure fields"
    wanted_name = "SuperHints"
    wanted_hotkey = "Shift-A"

    def init(self):
        print("[+] SuperHint Init")
        return MyPlugmod()


def PLUGIN_ENTRY():
    return MyPlugin()