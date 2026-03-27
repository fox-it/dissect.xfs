from __future__ import annotations


class Error(Exception):
    pass


class UnsupportedDataforkException(Error):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class SymlinkUnavailableException(Error):
    pass
