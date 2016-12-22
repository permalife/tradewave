# Create your tasks here
from __future__ import absolute_import, unicode_literals
from celery import shared_task

from tradewave import config

import logging
import mandrill

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@shared_task(bind=True)
def add(self, x, y):
    logger.info('Django request: %s', self.request)


@shared_task(bind=True)
def sendTransactionalEmail(self, template_name, template_content, merge_vars, recipient_email):
    mandrill_client = mandrill.Mandrill(config.MANDRILL_API_KEY)
    message = {
        'from_email': 'info@tradewave.co',
        'to': [{
            'email': recipient_email,
            'type': 'to'
        }],
        'global_merge_vars': merge_vars
    }

    mandrill_client.messages.send_template(
        template_name=template_name,
        template_content=template_content,
        message=message
    )
