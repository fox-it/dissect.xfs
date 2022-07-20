class Error(Exception):
    pass


class UnsupportedDataforkException(Error):
    pass


class FileNotFoundError(Error):
    pass


class NotADirectoryError(Error):
    pass


class NotASymlinkError(Error):
    pass


class SymlinkUnavailableException(Error):
    pass
