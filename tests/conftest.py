import os

from hypothesis import settings

settings.register_profile("ci", max_examples=40, derandomize=True, deadline=None)
settings.register_profile("local", max_examples=120, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "local"))
