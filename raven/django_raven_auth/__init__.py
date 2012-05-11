from django.conf import settings

def getsetting(name, default=None):
    """Gets a django setting value by name, or the default if no value is set.
    """
    try:
        # For some reason there is no sensible way to check if a setting is 
        # defined...
        return settings.__getattr__(name)
    except AttributeError:
        return default
