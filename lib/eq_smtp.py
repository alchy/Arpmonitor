#!/usr/bin/python
# -*- coding: utf-8 -*-

import smtplib


def sendmail(subject='<No Subject>', content='<No Body>'):

    sender = 'arpmonitor@secarp1.cz.money.ge.com'
    receivers = ['arpmonitor']

    head = 'From: Arpmonitor <arpmonitor@secarp1.cz.money.ge.com>'
    head += '\nTo: Arpmonitor Mailing List <arpmonitor>'
    head += '\nSubject: %s' % subject
    head += '\n'

    try:
        smtpObj = smtplib.SMTP('localhost')
        smtpObj.sendmail(sender, receivers, head + content)
        print '[i] email sent: %s' % subject
    except smtplib.SMTPException:

        print '[!] unable to send email: %s' % subject

