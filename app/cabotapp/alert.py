from os import environ as env

from django.conf import settings
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.template import Context, Template

from twilio.rest import TwilioRestClient
from twilio import twiml
import requests
import logging

from time import strftime,gmtime,time
import urllib2
import hmac
import hashlib
import base64
import string

logger = logging.getLogger(__name__)

email_template = """Service {{ service.name }} {{ scheme }}://{{ host }}{% url service pk=service.id %} {% if service.overall_status != service.PASSING_STATUS %}alerting with status: {{ service.overall_status }}{% else %}is back to normal{% endif %}.
{% if service.overall_status != service.PASSING_STATUS %}
CHECKS FAILING:{% for check in service.all_failing_checks %}
  FAILING - {{ check.name }} - Type: {{ check.check_category }} - Importance: {{ check.get_importance_display }}{% endfor %}
{% if service.all_passing_checks %}
Passing checks:{% for check in service.all_passing_checks %}
  PASSING - {{ check.name }} - Type: {{ check.check_category }} - Importance: {{ check.get_importance_display }}{% endfor %}
{% endif %}
{% endif %}
"""

hipchat_template = "Service {{ service.name }} {% if service.overall_status == service.PASSING_STATUS %}is back to normal{% else %}reporting {{ service.overall_status }} status{% endif %}: {{ scheme }}://{{ host }}{% url service pk=service.id %}. {% if service.overall_status != service.PASSING_STATUS %}Checks failing:{% for check in service.all_failing_checks %} {{ check.name }}{% if check.last_result.error %} ({{ check.last_result.error|safe }}){% endif %}{% endfor %}{% endif %}{% if alert %}{% for alias in users %} @{{ alias }}{% endfor %}{% endif %}"

#sms_template = "Service {{ service.name }} {% if service.overall_status == service.PASSING_STATUS %}is back to normal{% else %}reporting {{ service.overall_status }} status{% endif %}: {{ scheme }}://{{ host }}{% url service pk=service.id %}"
sms_template = "Service {{ service.name }} {% if service.overall_status == service.PASSING_STATUS %}is back to normal{% else %}reporting {{ service.overall_status }} status{% endif %}: {{ scheme }}://{{ host }}{% url service pk=service.id %}. {% if service.overall_status != service.PASSING_STATUS %}Checks failing:{% for check in service.all_failing_checks %} {{ check.name }}{% if check.last_result.error %} ({{ check.last_result.error|safe }}){% endif %}{% endfor %}{% endif %}"

telephone_template = "This is an urgent message from Arachnys monitoring. Service \"{{ service.name }}\" is erroring. Please check Cabot urgently."


def send_alert(service, duty_officers=None):
    users = service.users_to_notify.all()
    if service.email_alert:
        send_email_alert(service, users, duty_officers)
    if service.hipchat_alert:
        send_hipchat_alert(service, users, duty_officers)
    if service.sms_alert:
        send_sns_alert(service)
        send_sms_alert(service, users, duty_officers)
    if service.telephone_alert:
        send_telephone_alert(service, users, duty_officers)


def send_email_alert(service, users, duty_officers):
    emails = [u.email for u in users if u.email]
    if not emails:
        return
    c = Context({
        'service': service,
        'host': settings.WWW_HTTP_HOST,
        'scheme': settings.WWW_SCHEME
    })
    if service.overall_status != service.PASSING_STATUS:
        if service.overall_status == service.CRITICAL_STATUS:
            emails += [u.email for u in duty_officers]
        subject = '%s status for service: %s' % (
            service.overall_status, service.name)
    else:
        subject = 'Service back to normal: %s' % (service.name,)
    t = Template(email_template)
    send_mail(
        subject=subject,
        message=t.render(c),
        from_email='Cabot <%s>' % settings.CABOT_FROM_EMAIL,
        recipient_list=emails,
    )


def send_hipchat_alert(service, users, duty_officers):
    alert = True
    hipchat_aliases = [u.profile.hipchat_alias for u in users if hasattr(
        u, 'profile') and u.profile.hipchat_alias]
    if service.overall_status == service.WARNING_STATUS:
        alert = False  # Don't alert at all for WARNING
    if service.overall_status == service.ERROR_STATUS:
        if service.old_overall_status in (service.ERROR_STATUS, service.ERROR_STATUS):
            alert = False  # Don't alert repeatedly for ERROR
    if service.overall_status == service.PASSING_STATUS:
        color = 'green'
        if service.old_overall_status == service.WARNING_STATUS:
            alert = False  # Don't alert for recovery from WARNING status
    else:
        color = 'red'
        if service.overall_status == service.CRITICAL_STATUS:
            hipchat_aliases += [u.profile.hipchat_alias for u in duty_officers if hasattr(
                u, 'profile') and u.profile.hipchat_alias]
    c = Context({
        'service': service,
        'users': hipchat_aliases,
        'host': settings.WWW_HTTP_HOST,
        'scheme': settings.WWW_SCHEME,
        'alert': alert,
    })
    message = Template(hipchat_template).render(c)
    _send_hipchat_alert(message, color=color, sender='Cabot/%s' % service.name)


def _send_hipchat_alert(message, color='green', sender='Cabot'):
    room = settings.HIPCHAT_ALERT_ROOM
    api_key = settings.HIPCHAT_API_KEY
    url = settings.HIPCHAT_URL
    resp = requests.post(url + '?auth_token=' + api_key, data={
        'room_id': room,
        'from': sender[:15],
        'message': message,
        'notify': 1,
        'color': color,
        'message_format': 'text',
    })


def send_sms_alert(service, users, duty_officers):
    client = TwilioRestClient(
        settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    mobiles = [u.profile.prefixed_mobile_number for u in users if hasattr(
        u, 'profile') and u.profile.mobile_number]
    if service.is_critical:
        mobiles += [u.profile.prefixed_mobile_number for u in duty_officers if hasattr(
            u, 'profile') and u.profile.mobile_number]
    c = Context({
        'service': service,
        'host': settings.WWW_HTTP_HOST,
        'scheme': settings.WWW_SCHEME,
    })
    message = Template(sms_template).render(c)
    mobiles = list(set(mobiles))
    for mobile in mobiles:
        try:
            client.sms.messages.create(
                to=mobile,
                from_=settings.TWILIO_OUTGOING_NUMBER,
                body=message,
            )
        except Exception, e:
            logger.exception('Error sending twilio sms: %s' % e)

def send_sns_alert(service):
    if settings.SNS_AWS_ACCESS_ID is None:
        return;

    c = Context({
        'service': service,
        'host': settings.WWW_HTTP_HOST,
        'scheme': settings.WWW_SCHEME,
    })
    message = Template(sms_template).render(c)
    amzsnshost = 'sns.us-east-1.amazonaws.com'
    params = {'TopicArn' : settings.SNS_TOPIC,
            'Message' : message,
            'Timestamp' : strftime("%Y-%m-%dT%H:%M:%S.000Z", gmtime(time())),
            'AWSAccessKeyId' : settings.SNS_AWS_ACCESS_ID,
            'Action' : 'Publish',
            'SignatureVersion' : '2',
            'SignatureMethod' : 'HmacSHA256',
            } 
    cannqs=string.join(["%s=%s"%(urllib2.quote(key),urllib2.quote(params[key], safe='-_~')) \
                                for key in sorted(params.keys())],'&')
    string_to_sign=string.join(["GET",amzsnshost,"/",cannqs],'\n')
    sig=base64.b64encode(hmac.new(settings.SNS_AWS_ACCESS_KEY, string_to_sign, digestmod=hashlib.sha256).digest())
    url="http://%s/?%s&Signature=%s"%(amzsnshost,cannqs,urllib2.quote(sig))
    try:
        return urllib2.urlopen(url).read()
    except urllib2.HTTPError, exception:
        logger.exception("Error %s (%s):\n%s"%(exception.code,exception.msg,exception.read()));


def send_telephone_alert(service, users, duty_officers):
    # No need to call to say things are resolved
    if service.overall_status != service.CRITICAL_STATUS:
        return
    client = TwilioRestClient(
        settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    mobiles = [u.profile.prefixed_mobile_number for u in duty_officers if hasattr(
        u, 'profile') and u.profile.mobile_number]
    url = 'http://%s%s' % (settings.WWW_HTTP_HOST,
                           reverse('twiml-callback', kwargs={'service_id': service.id}))
    for mobile in mobiles:
        try:
            client.calls.create(
                to=mobile,
                from_=settings.TWILIO_OUTGOING_NUMBER,
                url=url,
                method='GET',
            )
        except Exception, e:
            logger.exception('Error making twilio phone call: %s' % e)


def telephone_alert_twiml_callback(service):
    c = Context({'service': service})
    t = Template(telephone_template).render(c)
    r = twiml.Response()
    r.say(t, voice='woman')
    r.hangup()
    return r
