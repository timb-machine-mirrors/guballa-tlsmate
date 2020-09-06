# -*- coding: utf-8 -*-
"""Module containing Alert exceptions
"""


class Alert(Exception):
    pass

class FatalAlert(Exception):

    def __init__(self, message, description):
        self.description = description
        self.message = message

