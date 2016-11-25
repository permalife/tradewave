from django import template

import logging

register = template.Library()

logging.basicConfig(level=logging.DEBUG, filename="log/views.log")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

@register.filter
def subtract(value, arg):
    return value - arg

@register.filter
def subtractfirst(value, arg):
    #logger.info(arg.values)
    return value - arg.values()[0]['amount']

@register.filter
def firstname(arg):
    #logger.info(arg.values)
    return arg.values()[0]['name']

@register.filter
def firstamount(arg):
    #logger.info(arg.values)
    return arg.values()[0]['amount']
