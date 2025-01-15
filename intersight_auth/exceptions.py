class IntersightAuthKeyException(Exception):
    """Raised when there is an error with the supplied key"""

    pass


class IntersightAuthConfigException(Exception):
    """Raised when there is an error with the supplied configuration"""

    pass


class IntersightAuthOAuthException(Exception):
    """Raised when an error occurs during OAuth handling (e.g. authentication error retreiving token)"""

    pass
