import os
import idc
import json
import idaapi
import ida_idaapi
import ida_hexrays
import ida_kernwin
import ida_netnode
import ida_typeinf

NODE_NAME = "$ SuperHint"


class hint_storage():
    def __init__(self):
        self.node = ida_netnode.netnode(NODE_NAME, 0, False)
        if self.node == idaapi.BADNODE or self.node.getblob(0, 'D') == None:
            print("[+] create new")
            self.node = ida_netnode.netnode(NODE_NAME, 0, True)
            self.struct_db = {}
        else:
            print("[+] has netnode")
            self.struct_db = json.loads(self.node.getblob(0, 'D').decode('utf-8'))
        
        print(self.struct_db)

    def load_hint_storage(self):
        self.struct_db = json.loads(self.node.getblob(0, 'D').decode('utf-8'))


    def store_hint_storage(self):
        struct_db_json = json.dumps(self.struct_db)
        self.node.setblob(struct_db_json.encode('utf-8'), 0, 'D')

    def get_struct_hint(self, ordinal):

        if ordinal not in self.struct_db:
            return 0
        else:
            return self.struct_db[ordinal]

    def set_struct_hint(self, ordinal, offset, data):
        return
    
    def add_new_struct_hint(self, ordinal):
        self.struct_db[ordinal] = {}


class HintManager(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super(HintManager, self).__init__()
        self.hint_storage  = hint_storage()

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
            struct_tid = struct_info.get_tid()
            ordinal = str(ida_typeinf.get_tid_ordinal(struct_tid))

            member_offset = str(udm_info.offset)
            target_struct = self.hint_storage.get_struct_hint(ordinal)

            if(int(ordinal) == 0 or target_struct == 0 or member_offset not in target_struct): 
                return 0
    
            return 5, target_struct[member_offset], 1000

        return 0

    def edit_hint(self, cmt):
        return ida_kernwin.ask_text(1000, cmt, "Edit hint")

    def set_local_var_hint(self, lvar):
        new_hint = self.edit_hint(lvar.cmt)

        if(new_hint == None):
            new_hint = lvar.cmt

        lvar.cmt = new_hint
        

    def hotkey_pressed(self):
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
            self.set_local_var_hint(lvar)
            return


        udm_info = idaapi.udm_t()
        struct_info = idaapi.tinfo_t()
        member_idx = item.get_udm(udm_info, struct_info)
        if(member_idx != -1):

            struct_tid = struct_info.get_tid()
            ordinal = str(ida_typeinf.get_tid_ordinal(struct_tid))


            if self.hint_storage.get_struct_hint(ordinal) == 0:
                self.hint_storage.add_new_struct_hint(ordinal)


            target_struct = self.hint_storage.get_struct_hint(ordinal)

            member_offset = str(udm_info.offset)
            if member_offset not in target_struct:
                target_struct[member_offset] = ""
            
            new_hint = self.edit_hint(target_struct[member_offset])

            if(new_hint == None):
                new_hint = target_struct[member_offset]

            target_struct[member_offset] = new_hint    
            return
    



class MyPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.init_state = 0
        self.filename = idc.get_root_filename()
        self.osw_hint_manager = None

    def __del__(self):
        self.osw_hint_manager.hint_storage.store_hint_storage()
        self.remove_hint_hook()
        


    def install_hint_hook(self):

        if not ida_hexrays.init_hexrays_plugin():
            print("[-] Hex-Rays Decompiler is not loaded.")
        else:
             print("[+] Hex-Rays Decompiler is loaded.")


        self.remove_hint_hook()

        self.osw_hint_manager = HintManager()
        if self.osw_hint_manager.hook() == 0:
            print("[!] HintManager Error")

        print("[+] hint hook done")


    def remove_hint_hook(self):
        if self.osw_hint_manager:
            self.osw_hint_manager.unhook()
            self.osw_hint_manager = None

    def run(self, arg):        
        print("[+] run called")

        if(self.osw_hint_manager == None):
            self.install_hint_hook()
        else:
            self.osw_hint_manager.hotkey_pressed()
        

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