"""
Exceptions used in ripbin
"""


# General Error


class RipbinRegistryError(Exception):
    """General Ripbin DB Registry Errror"""

class RipbinAnalysisError(Exception):
    """General Analysis Error"""


class RipbinDbError(Exception):
    """General Ripbin Db Error"""



# Specific Error 


class AnalysisExistsError(RipbinAnalysisError):
    """Existing Analysis file exists"""


