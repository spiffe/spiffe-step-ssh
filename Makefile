default:
	@echo Targets:
	@echo "  install"

install:
	mkdir -p $(DESTDIR)/usr/lib/systemd/system/sshd.service.d
	mkdir -p $(DESTDIR)/usr/libexec/spiffe-step-ssh
	mkdir -p $(DESTDIR)/etc/spiffe/step-ssh
	install scripts/update.sh  $(DESTDIR)/usr/libexec/spiffe-step-ssh
	install scripts/reset.sh  $(DESTDIR)/usr/libexec/spiffe-step-ssh
	install systemd/spiffe-step-ssh@.service $(DESTDIR)/usr/lib/systemd/system
	install conf/10-spiffe-step-ssh.conf $(DESTDIR)/usr/lib/systemd/system/sshd.service.d
	install systemd/spiffe-step-ssh-cleanup.service $(DESTDIR)/usr/lib/systemd/system

install-server:
	mkdir -p $(DESTDIR)/usr/lib/systemd/system
	mkdir -p $(DESTDIR)/usr/libexec/spiffe/step-ssh-server
	mkdir -p $(DESTDIR)/etc/spiffe/step-ssh-server
	mkdir -p $(DESTDIR)/usr/sbin
	install systemd/spiffe-step-ssh-server@.service $(DESTDIR)/usr/lib/systemd/system
	install systemd/spiffe-step-ssh-fetchca@.service $(DESTDIR)/usr/lib/systemd/system
	install scripts/server.sh  $(DESTDIR)/usr/libexec/spiffe/step-ssh-server/main
	install scripts/setup-spiffe-step-ssh-server  $(DESTDIR)/usr/sbin
	install conf/ssh_x5c.tpl  $(DESTDIR)/usr/libexec/spiffe/step-ssh-server
	install conf/nginx-fetchca.conf  $(DESTDIR)/usr/libexec/spiffe/step-ssh-server
	install conf/helper-fetchca.conf  $(DESTDIR)/usr/libexec/spiffe/step-ssh-server
