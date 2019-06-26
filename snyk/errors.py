class SnykError(Exception):
    pass


class SnykNotFoundError(SnykError):
    pass


class SnykOrganizationNotFoundError(SnykError):
    pass


class SnykProjectNotFoundError(SnykError):
    pass


class SnykNotImplementedError(SnykError):
    pass
