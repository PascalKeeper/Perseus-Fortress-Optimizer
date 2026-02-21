import ctypes
from ctypes import wintypes
import time
import sys
import os
import uuid

# --- KERNEL ACCESS ---
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
psapi = ctypes.windll.psapi
powrprof = ctypes.windll.powrprof

# --- CONSTANTS & STRUCTS ---
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SET_QUOTA = 0x0100 # Required for EmptyWorkingSet
QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x00000001
QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000002
ProcessMemoryPriority = 5
MEM_PRIORITY_VERY_LOW = 1
MEM_PRIORITY_NORMAL = 5

class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_byte),
        ("BatteryFlag", ctypes.c_byte),
        ("BatteryLifePercent", ctypes.c_byte),
        ("Reserved1", ctypes.c_byte),
        ("BatteryLifeTime", ctypes.c_ulong),
        ("BatteryFullLifeTime", ctypes.c_ulong),
    ]

class MEMORY_PRIORITY_INFORMATION(ctypes.Structure):
    _fields_ = [("MemoryPriority", ctypes.c_ulong)]

# --- CORE LOGIC ---

def get_power_status():
    """Reads hardware power rails directly."""
    status = SYSTEM_POWER_STATUS()
    if kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        return status
    return None

def set_process_efficiency(pid, mode):
    """
    Directly manipulates process memory pages and priority.
    Mode 0: SURVIVAL (Trim RAM, Low Priority)
    Mode 1: FORTRESS (Max Priority, Lock RAM)
    """
    try:
        # Open process with specific rights to avoid Access Denied on system procs
        # Added PROCESS_SET_QUOTA (0x0100) which is explicitly required for EmptyWorkingSet
        h_proc = kernel32.OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, False, pid)
        if not h_proc: return

        if mode == 0: # SURVIVAL / BACKGROUND
            # 1. Force OS to reclaim RAM from this process immediately
            psapi.EmptyWorkingSet(h_proc)
            
            # 2. Set to IDLE priority (64)
            kernel32.SetPriorityClass(h_proc, 0x00000040) 
            
            # 3. Lower Memory Priority to 'Very Low'
            mem_pri = MEMORY_PRIORITY_INFORMATION()
            mem_pri.MemoryPriority = MEM_PRIORITY_VERY_LOW
            kernel32.SetProcessInformation(h_proc, ProcessMemoryPriority, ctypes.byref(mem_pri), ctypes.sizeof(mem_pri))

        elif mode == 1: # FORTRESS / FOCUS
            # 1. Set to HIGH priority (128) - Realtime (256) is dangerous, High is stable/fast
            kernel32.SetPriorityClass(h_proc, 0x00000080)
            
            # 2. Ensure Memory Priority is Normal/High
            mem_pri = MEMORY_PRIORITY_INFORMATION()
            mem_pri.MemoryPriority = MEM_PRIORITY_NORMAL
            kernel32.SetProcessInformation(h_proc, ProcessMemoryPriority, ctypes.byref(mem_pri), ctypes.sizeof(mem_pri))
        
        kernel32.CloseHandle(h_proc)
    except Exception:
        pass # Silently fail on protected system processes (CSRSS, etc.)

def get_active_pid():
    """Finds exactly what the human is looking at right now."""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value

def set_global_power_scheme(ac_plugged):
    """Bypasses powercfg.exe to hit PowrProf.dll directly using proper GUID structs."""
    # Convert standard string GUIDs to C-compatible byte buffers (little-endian bytes)
    high_perf_guid = ctypes.c_buffer(uuid.UUID('8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c').bytes_le)
    power_saver_guid = ctypes.c_buffer(uuid.UUID('a1841308-3541-4fab-bc81-f71556f20b4a').bytes_le)
    
    if ac_plugged:
        powrprof.PowerSetActiveScheme(None, ctypes.byref(high_perf_guid))
    else:
        powrprof.PowerSetActiveScheme(None, ctypes.byref(power_saver_guid))

def fortress_loop():
    print(">> PROTOCOL GIFT_FOR_MOTHER_EARTH: INITIALIZED.")
    print(">> MONITORING SYSTEM VITALS...")
    
    last_trim_time = 0
    trim_interval = 30 # Trim background RAM every 30s
    
    while True:
        # 1. READ VITALS
        power = get_power_status()
        if not power:
            time.sleep(1)
            continue
            
        is_ac = power.ACLineStatus == 1
        battery_level = power.BatteryLifePercent
        
        # 2. DETERMINE STATE
        # BABY-FIRST SAFEGUARD: If on battery and < 20%, force survival
        survival_mode = (not is_ac) and (battery_level < 20)
        
        # 3. ENFORCE POWER PLAN
        set_global_power_scheme(not survival_mode)

        # 4. ORCHESTRATE ACTIVE TASK
        active_pid = get_active_pid()
        if active_pid > 0:
            set_process_efficiency(active_pid, 1) # Boost Active

        # 5. GARBAGE COLLECT BACKGROUND (The "Cross-Resource Sharing")
        current_time = time.time()
        if current_time - last_trim_time > trim_interval:
            # For this Python kernel, we trim the working set of the script itself
            # Note: In a full impl, iterate via CreateToolhelp32Snapshot to trim other non-active PIDs.
            kernel32.SetProcessWorkingSetSize(kernel32.GetCurrentProcess(), -1, -1) 
            last_trim_time = current_time

        # 6. CYCLE
        # Fast heartbeat for responsiveness, slower if in survival
        time.sleep(0.5 if not survival_mode else 2.0)

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("!! PERSEUS FORTRESS REQUIRES ADMIN. RESTARTING ELEVATED...")
        
        # Wrap the script path in quotes to handle spaces in directories securely
        script_path = os.path.abspath(sys.argv[0])
        params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        
        # Execute script with Administrator privileges
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}" {params}', None, 1)
        
        if ret <= 32:
            print("Failed to elevate privileges. Exiting.")
        sys.exit()
    else:
        try:
            fortress_loop()
        except KeyboardInterrupt:
            print("\n>> RELEASING CONTROL. Shutting down smoothly.")
