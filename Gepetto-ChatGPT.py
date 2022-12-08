import functools
import json
import idaapi
import ida_hexrays
import ida_kernwin
import idc
# import openai
import os
import re
import textwrap
import threading
from revChatGPT.revChatGPT import Chatbot

config = {
     "email": "<YOUR_EMAIL>",
     "password": "<YOUR_PASSWORD>"#,
    #"session_token": "",
     #Use session_token or email/password. But the session_token has a very short validity
    #"proxy": "127.0.0.1:7890"
}
ZH_CN = True  # 是否使用中文代码解释 # Use Chinese explain


# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class Gepetto_CHATPlugin(idaapi.plugin_t):
    flags = 0
    explain_action_name = "Gepetto_CHAT:explain_function_CHAT"
    explain_menu_path = "Edit/Gepetto_CHAT/Explain function_CHAT"
    rename_action_name = "Gepetto_CHAT:rename_function_CHAT"
    rename_menu_path = "Edit/Gepetto_CHAT/Rename variables_CHAT"
    wanted_name = 'Gepetto_CHAT'
    wanted_hotkey = ''
    comment = "Uses ChatGPT to enrich the decompiler's output"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(self.explain_action_name,
                                              'Explain function_CHAT',
                                              ExplainHandler(),
                                              "Ctrl+Alt+G",
                                              'Use ChatGPT to explain the currently selected function',
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, idaapi.SETMENU_APP)

        # Variable renaming action
        rename_action = idaapi.action_desc_t(self.rename_action_name,
                                             'Rename variables_CHAT',
                                             RenameHandler(),
                                             "Ctrl+Alt+R",
                                             "Use ChatGPT to rename this function's variables",
                                             199)
        idaapi.register_action(rename_action)
        idaapi.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        if self.menu:
            self.menu.unhook()
        return


# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, Gepetto_CHATPlugin.explain_action_name, "Gepetto_CHAT/")
            idaapi.attach_action_to_popup(form, popup, Gepetto_CHATPlugin.rename_action_name, "Gepetto_CHAT/")


# -----------------------------------------------------------------------------

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("ChatGPT query finished!")


# -----------------------------------------------------------------------------

class ExplainHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying ChatGPT for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        if ZH_CN:
            query_model_async(
                "对下面的C语言伪代码函数进行分析 推测关于该函数的使用环境和预期目的详细的函数功能等信息 并为这个函数取一个新的名字 不要返回其他的内容 (开始前加上GPTSTART 结束后加上GPTEND字符串)\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        else:
            query_model_async(
                "Can you explain what the following C function does and suggest a better name for it?(Add GPTSTART before the beginning of the conversation and GPTEND after the end.)\n"
                + str(decompiler_output),
                functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# -----------------------------------------------------------------------------

def rename_callback(address, view, response):
    """
    Callback that extracts a JSON array of old names and new names from the
    response and sets them in the pseudocode.
    :param address: The address of the function to work on
    :param view: A handle to the decompiler window
    :param response: The response from ChatGPT
    """
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        print(f"Error: couldn't extract a response from ChatGPT's output:\n{response}")
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        print(f"The data returned by the model cannot be parsed. Asking the model to fix it...")
        query_model_async("Please fix the following JSON document:\n" + j.group(0),
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=view))
        return

    # The rename function needs the start address of the function
    function_addr = idaapi.get_func(address).start_ea

    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update possible names left in the function comment
    comment = idc.get_func_cmt(address, 0)
    if comment and len(replaced) > 0:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    # Refresh the window to show the new names
    if view:
        view.refresh_view(True)
    print(f"ChatGPT query finished! {len(replaced)} variable(s) renamed.")


# -----------------------------------------------------------------------------

class RenameHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from ChatGPT and updates the
    decompiler's output.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(
            "Analyze the following C function. Suggest better variable names, reply with a JSON array where keys are the original names and values are the proposed names. Do not explain anything, only print the JSON dictionary(Add GPTSTART before the beginning of the reply and GPTEND after the end.):\n" + str(
                decompiler_output),
            functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# =============================================================================
# ChatGPT interaction
# =============================================================================

def query_model(query, cb):
    """
    Function which sends a query to ChatGPT and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to ChatGPT
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        chatbot = Chatbot(config, conversation_id=None)
        response = chatbot.get_chat_response(query)['message']
        if response.find("GPTSTART") == -1:
            raise Exception("Unexpected response: " + response)
        times = 1
        retry = 0
        data = response
        print(f"response[" + str(times) + "]: " + response)
        while response.find("GPTEND") == -1:
            try:
                times += 1
                response = chatbot.get_chat_response("next")['message']
                if response.find("GPTSTART") != -1:
                    times = 99
                    raise Exception("Duplicate responses appear: " + response)
                print(f"response[" + str(times) + "]: " + response)
                data += response
                # print(message)
                times = times - retry
                retry = 0
            except Exception as e:
                if times > 5:
                    raise Exception("Request 5 times and still not return full results: " + response)
                if retry > 3:
                    raise Exception("Retry 3 times and the request still fails: " + response)
                retry += 1
        ida_kernwin.execute_sync(functools.partial(cb, response=data.replace('GPTEND', '').replace('GPTSTART', '')),
                                 ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")


# -----------------------------------------------------------------------------

def query_model_async(query, cb):
    """
    Function which sends a query to ChatGPT and calls a callback when the response is available.
    :param query: The request to send to ChatGPT
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to ChatGPT sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    return Gepetto_CHATPlugin()
