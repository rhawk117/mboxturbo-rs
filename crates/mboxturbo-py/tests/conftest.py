"""Hypothesis run budgets, chosen with HYPOTHESIS_PROFILE (dev by default)."""

import os

from hypothesis import settings

settings.register_profile('dev', max_examples=75, deadline=None)
settings.register_profile('ci', max_examples=500, deadline=None)
settings.load_profile(os.getenv('HYPOTHESIS_PROFILE', 'dev'))
