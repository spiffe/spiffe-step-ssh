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
