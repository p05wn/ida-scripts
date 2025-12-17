import idc
import json
import idaapi
import idautils
import ida_name
import ida_idaapi
import ida_hexrays
import ida_kernwin
import ida_netnode
import ida_typeinf


NODE_NAME = "$ SuperHint"

class hint_storage(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)
        self.node = ida_netnode.netnode(NODE_NAME, 0, False)
        if self.node == idaapi.BADNODE:
            print("[+] create new")
            self.node = ida_netnode.netnode(NODE_NAME, 0, True)
            self.struct_db = {}
            self.global_func_db = {}
        else:
            if self.node.getblob(0, 'D') == None:
                self.struct_db = {}
            else:
                self.struct_db = json.loads(self.node.getblob(0, 'D').decode('utf-8'))

            if self.node.getblob(8, 'D') == None:
                self.global_func_db = {}
            else:
                self.global_func_db = json.loads(self.node.getblob(8, 'D').decode('utf-8'))      
        
        print(self.struct_db)
        print(self.global_func_db)


    def savebase(self):
        print("")
        self.update_struct_db()
        self.update_global_func_db()


    def update_struct_db(self):
        
        for key in self.struct_db.keys():
            target_ti = idaapi.get_idati()
            struct_name = ida_typeinf.get_numbered_type_name(target_ti, int(key))

            if struct_name == "" or struct_name == None:
                ordinal = ida_typeinf.get_type_ordinal(None, self.struct_db[key]["name"])

                if(ordinal == None or ordinal == 0):
                    self.struct_db.pop(key)
                else:
                    self.struct_db[str(ordinal)] = self.struct_db.pop(key)

                return 
            
            if(struct_name != self.struct_db[key]["name"]):
                self.struct_db[key]["name"] = struct_name


    def update_global_func_db(self):
        
        for key in self.global_func_db.keys():
            current_name = ida_name.get_name(int(key))
            
            if current_name == 0 or current_name == "":
                self.global_func_db.pop(key)
                return

            prev_name = self.global_func_db[key]["name"]
            if(prev_name != current_name):
                self.global_func_db[key]["name"] = current_name

        print(self.global_func_db)


    def store_hint_storage(self):
        struct_db_json = json.dumps(self.struct_db)
        global_func_db_json = json.dumps(self.global_func_db)

        self.node.setblob(struct_db_json.encode('utf-8'), 0, 'D')
        self.node.setblob(global_func_db_json.encode('utf-8'), 8, 'D') 

    def get_struct_hint(self, ordinal):
        if ordinal not in self.struct_db:
            return 0
        else:
            return self.struct_db[ordinal]
                
    def get_globalvar_func_db(self, ea):
        if ea not in self.global_func_db:
            return 0
        else:
            return self.global_func_db[ea]

    def new_struct_hint(self, ordinal):
        if ordinal not in self.struct_db:
            target_ti = idaapi.get_idati()
            self.struct_db[ordinal] = {}
            self.struct_db[ordinal]["name"] = ida_typeinf.get_numbered_type_name(target_ti, int(ordinal))

        return self.struct_db[ordinal]

    def new_globalvar_func_db(self, target_ea):
        if target_ea not in self.global_func_db:
            self.global_func_db[target_ea] = {}
            self.global_func_db[target_ea]["hint"] = ""
            self.global_func_db[target_ea]["name"] = ida_name.get_name(int(target_ea))
        
        return self.global_func_db





class HintManager(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super(HintManager, self).__init__()
        self.hint_storage  = hint_storage()
        self.hint_storage.hook()

    def create_hint(self, vu):
        hint = ""
        viewer = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(viewer) != ida_kernwin.BWN_PSEUDOCODE:
            print("[!] Not in pesudocode")
            return

        if vu.get_current_item(idaapi.USE_KEYBOARD):
            item_expr = vu.item.e
            item_citype = vu.item.citype
        else:
            return 0


        if(vu.item.get_lvar()):
            lvar = vu.item.get_lvar()
            hint = lvar.cmt
        
        elif(item_citype == idaapi.VDI_EXPR):

            if(item_expr.op == idaapi.cot_memref or item_expr.op == idaapi.cot_memptr):
                udm_info = idaapi.udm_t()
                struct_info = idaapi.tinfo_t()
                member_idx = vu.item.get_udm(udm_info, struct_info)

                if(member_idx != -1):
                    struct_tid = struct_info.get_tid()
                    ordinal = str(ida_typeinf.get_tid_ordinal(struct_tid))

                    member_offset = str(udm_info.offset)

                    if(int(ordinal) == 0):
                        return 0

                    target_struct = self.hint_storage.get_struct_hint(ordinal)

                    if(target_struct == 0 or member_offset not in target_struct):
                        return 0
                    
                    hint = target_struct[member_offset]

            elif(item_expr.op == idaapi.cot_obj):
                target_global_func = self.hint_storage.get_globalvar_func_db(str(item_expr.obj_ea))
                if(target_global_func == 0):
                    return 0

                hint = target_global_func["hint"]

            else:
                return 0


        if(hint == ""):
            return 0

        return 5, hint + "\n\n", 1000
        

    def edit_hint(self, cmt):
        return ida_kernwin.ask_text(1000, cmt, "Edit hint")

    def set_local_var_hint(self, vu, lvar):
        new_hint = self.edit_hint(lvar.cmt)

        if(new_hint == None):
            new_hint = lvar.cmt

        vu.set_lvar_cmt(lvar, new_hint)
        

    def hotkey_pressed(self):

        viewer = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(viewer) != ida_kernwin.BWN_PSEUDOCODE:
            print("[!] Not in pesudocode")
            return

        vu = idaapi.get_widget_vdui(viewer)
        if vu.get_current_item(idaapi.USE_KEYBOARD):
                item_expr = vu.item.e
                item_citype = vu.item.citype
        else:
            return


        if(vu.item.get_lvar()):
            lvar = vu.item.get_lvar()
            self.set_local_var_hint(vu, lvar)
            return

        elif(item_citype == idaapi.VDI_EXPR):
            if(item_expr.op == idaapi.cot_memref or item_expr.op == idaapi.cot_memptr):
                udm_info = idaapi.udm_t()
                struct_info = idaapi.tinfo_t()
                member_idx = vu.item.get_udm(udm_info, struct_info)
                if(member_idx != -1):
                
                    struct_tid = struct_info.get_tid()
                    ordinal = str(ida_typeinf.get_tid_ordinal(struct_tid))

                    if(ordinal == 0):
                        return

                    target_struct = self.hint_storage.new_struct_hint(ordinal)

                    member_offset = str(udm_info.offset)
                    if member_offset not in target_struct:
                        target_struct[member_offset] = ""

                    new_hint = self.edit_hint(target_struct[member_offset])

                    if(new_hint == None):
                        new_hint = target_struct[member_offset]

                    target_struct[member_offset] = new_hint    
                    return
                
            elif(item_expr.op == idaapi.cot_obj):
                target_ea = str(item_expr.obj_ea)
                target_db = self.hint_storage.new_globalvar_func_db(target_ea)
                new_hint = self.edit_hint(target_db[target_ea]["hint"])

                if(new_hint == None):
                    new_hint = target_db[target_ea]["hint"]

                target_db[target_ea]["hint"] = new_hint
                return



class MyPlugmod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.init_state = 0
        self.filename = idc.get_root_filename()
        self.osw_hint_manager = None

    def __del__(self):
        self.osw_hint_manager.hint_storage.store_hint_storage()
        self.osw_hint_manager.hint_storage.unhook()
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
        if(self.osw_hint_manager == None):
            self.install_hint_hook()
        else:
            self.osw_hint_manager.hotkey_pressed()
        

class MyPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_KEEP
    comment = "plugin for editing hints"
    help = "add/edit comments to hints. Supports local variable and structure fields"
    wanted_name = "SuperHint"
    wanted_hotkey = "Shift-A"

    def init(self):
        print("[+] SuperHint Init")
        return MyPlugmod()


def PLUGIN_ENTRY():
    return MyPlugin()