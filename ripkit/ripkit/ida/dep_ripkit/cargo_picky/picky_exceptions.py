class CrateBuildException(Exception):
    def __init__(self, message="Exception building crate"):
        self.message = message
        super().__init__(self.message)
