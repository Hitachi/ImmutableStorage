ARG BASEIMG
FROM $BASEIMG

RUN apk update
RUN apk add --no-cache rsyslog
RUN addgroup --system syslog
RUN adduser --system --ingroup syslog --no-create-home syslog
RUN adduser syslog adm
RUN adduser syslog tty
RUN mkdir -p /var/spool/rsyslog
RUN chmod 700 /var/spool/rsyslog
RUN chown syslog.adm /var/spool/rsyslog

RUN chgrp syslog /var/log
RUN chmod g+w /var/log

COPY ./rsyslog2imm /usr/local/bin/

#COPY ./rsyslog.conf /etc/rsyslog.conf

CMD ["/usr/sbin/rsyslogd"]
