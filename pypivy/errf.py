from __future__ import annotations
from pypivy.pivy_ctypes import *

class Errf(Exception):
    """
    A structured error object returned by libpivy APIs. Includes information
    about the location of the error in C code in the library, and possibly
    a 'cause' chain.
    """
    def __init__(self, ptr: c_void_p):
        self._ptr = ptr
        super().__init__(self.message)

    def __new__(cls, ptr: c_void_p) -> Errf:
        """
        Uses the `name` of the given errf_t pointer to locate a subclass of
        Errf with the same name. Returns an instance of that class. If no
        matching subclass exists, returns an instance of Errf itself.
        """
        name = libpivy.errf_name(ptr).decode('ascii')
        for scls in cls.__subclasses__():
            if scls.__name__ == name:
                return Exception.__new__(scls, ptr)
        return Exception.__new__(Errf, ptr)

    def __del__(self):
        libpivy.errf_free(self._ptr)
        self._ptr = None
    @property
    def name(self) -> str:
        """
        The name of the error type (e.g. "PCSCError" for an error originating
        in the PCSC library)
        """
        return libpivy.errf_name(self._ptr).decode('ascii')
    @property
    def message(self) -> str:
        """
        A short one-line summary of the error.
        """
        return libpivy.errf_message(self._ptr).decode('ascii')
    @property
    def function(self) -> str:
        """
        Name of the C function where the error occurred.
        """
        return libpivy.errf_function(self._ptr).decode('ascii')
    @property
    def file(self) -> str:
        """
        Name of the C source file where the error occurred.
        """
        return libpivy.errf_file(self._ptr).decode('ascii')
    @property
    def errno(self) -> int:
        """
        The system call 'errno' value which is associated with this error
        (if any).
        """
        return libpivy.errf_errno(self._ptr)
    @property
    def line(self) -> int:
        """
        Line in the C source file where the error occurred.
        """
        return libpivy.errf_line(self._ptr)
    @property
    def cause(self) -> Errf | None:
        """
        The cause of this error, if any.
        """
        ptr = libpivy.errf_cause(self._ptr)
        if ptr:
            return Errf(ptr)
        else:
            return None
    def caused_by(self, name: str) -> bool:
        """
        Returns True if this error, or any error in the cause chain attached,
        is named `name`.

        :param name: an errf_t name, e.g. "PCSCError"
        """
        v = libpivy.errf_caused_by(self._ptr, name.encode('ascii'))
        return (v == 1)
    def __str__(self) -> str:
        s = ''
        if self.__class__.__name__ != self.name:
            s = s + self.name + ': '
        s = s + self.message + '\n'
        s = s + '  in ' + self.function + ' (' + self.file + ':' + str(self.line) + ')'
        c = self.cause
        if c is not None:
            s = s + '\n' + c.__str__()
        return s

class PCSCError(Errf):
    pass
class ServiceError(Errf):
    pass
class PCSCContextError(Errf):
    pass
class DuplicateError(Errf):
    pass
class NotFoundError(Errf):
    pass
class IOError(Errf):
    pass
class FASCNFormatError(Errf):
    pass
class KeyAuthError(Errf):
    pass
class PermissionError(Errf):
    pass
class NotSupportedError(Errf):
    pass
