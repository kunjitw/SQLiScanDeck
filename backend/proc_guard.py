"""
Kill orphaned scanner subprocesses when THIS backend dies.

Graceful shutdown already terminates each engine (scan_manager.shutdown), but a HARD
kill -- Task Manager "End task", `taskkill /F`, a crash, power loss -- never runs it,
leaving sqlmap/ghauri (and their python launcher) hammering the target.

Fix (Windows, dependency-free via ctypes): create ONE Job Object with
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and assign every engine subprocess to it. The job
handle is held for this process's whole lifetime; when the process dies for ANY reason
the OS closes the handle and terminates every process still in the job. On non-Windows
(the tool is Windows-only, but stay safe) every function is a no-op.

All calls are best-effort: any failure just means we fall back to the previous behavior
(graceful-only cleanup), never an error to the caller.
"""
import sys
import threading

_JOB = None                # the job handle (int), False = tried-and-unavailable, None = untried
_LOCK = threading.Lock()   # guards the one-time lazy init of _JOB (assign() runs on many threads)
_KILL_ON_JOB_CLOSE = 0x2000
_JobObjectExtendedLimitInformation = 9


def _k32():
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    # 64-bit handles are pointers, not C ints -- set restypes or ctypes truncates them.
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    k.SetInformationJobObject.restype = wintypes.BOOL
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.AssignProcessToJobObject.restype = wintypes.BOOL
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.IsProcessInJob.restype = wintypes.BOOL
    k.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    k.CloseHandle.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k, ctypes, wintypes


def _job():
    """The process-wide kill-on-close Job Object handle, or None if unavailable.
    Double-checked locking: concurrent first-callers (ThreadPoolExecutor workers) must not
    each CreateJobObject (handle leak), and a failure result must not clobber a published one."""
    global _JOB
    if _JOB is not None:                 # fast path once initialized (handle or False)
        return _JOB or None
    with _LOCK:
        if _JOB is None:                 # first thread in creates it; the rest see the result
            _JOB = _create_job()
        return _JOB or None


def _create_job():
    """Create the kill-on-close job ONCE (called under _LOCK). Returns the handle, or False
    if unavailable (non-Windows, or any Win32 failure)."""
    if not sys.platform.startswith("win"):
        return False
    try:
        k, ctypes, wintypes = _k32()
        job = k.CreateJobObjectW(None, None)
        if not job:
            return False

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_uint64),
                        ("WriteOperationCount", ctypes.c_uint64),
                        ("OtherOperationCount", ctypes.c_uint64),
                        ("ReadTransferCount", ctypes.c_uint64),
                        ("WriteTransferCount", ctypes.c_uint64),
                        ("OtherTransferCount", ctypes.c_uint64)]

        class EXT(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = EXT()
        info.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
        if not k.SetInformationJobObject(job, _JobObjectExtendedLimitInformation,
                                         ctypes.byref(info), ctypes.sizeof(info)):
            k.CloseHandle(job)
            return False
        return job          # held for the process lifetime -- do NOT CloseHandle it
    except Exception:
        return False


def assign(pid):
    """Assign a spawned engine process to the kill-on-close job. Best-effort, no-op off Windows."""
    job = _job()
    if not job or not pid:
        return False
    try:
        k, ctypes, wintypes = _k32()
        PROCESS_SET_QUOTA, PROCESS_TERMINATE = 0x0100, 0x0001
        h = k.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, int(pid))
        if not h:
            return False
        ok = bool(k.AssignProcessToJobObject(job, h))
        k.CloseHandle(h)
        return ok
    except Exception:
        return False


def is_in_job(pid):
    """Test helper: is this pid in OUR job? (best-effort; False on any failure)."""
    job = _job()
    if not job or not pid:
        return False
    try:
        k, ctypes, wintypes = _k32()
        h = k.OpenProcess(0x0400, False, int(pid))   # PROCESS_QUERY_INFORMATION
        if not h:
            return False
        res = wintypes.BOOL(False)
        k.IsProcessInJob(h, job, ctypes.byref(res))
        k.CloseHandle(h)
        return bool(res.value)
    except Exception:
        return False
