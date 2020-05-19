TARGET:=ietf_ifaces.so

OBJ:= \
	config.o \
	main.o \
	state.o \

SR_PLUGINS_DIR="$(DESTDIR)/usr/lib64/sysrepo/plugins"

LDFLAGS+=-lsysrepo -lnel -lnel-route

.PHONY: clean all install uninstall clear_shm

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ -shared -fPIC $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^ -fPIC

clean:
	rm -f $(TARGET) $(OBJ)

clear_shm:
	rm /dev/shm/sr*

install: $(TARGET)
	echo "" >install_manifest.txt

	mkdir -p "$(SR_PLUGINS_DIR)"

	cp ietf_ifaces.so "$(SR_PLUGINS_DIR)"
	echo "$(SR_PLUGINS_DIR)/ietf_ifaces.so" >>install_manifest.txt

	killall sysrepo-plugind || true

	sysrepoctl -i ietf-interfaces.yang -s ./ || true
	sysrepoctl -c ietf-interfaces -p 644
	sysrepoctl -i ietf-ip.yang -s ./ || true
	sysrepoctl -c ietf-ip -p 644
	sysrepoctl -c ietf-interfaces -s ./ -e if-mib || true

	sysrepo-plugind

uninstall:
	killall sysrepo-plugind || true

	sysrepoctl -u ietf-ip || true
	sysrepoctl -u ietf-interfaces || true

	cat install_manifest.txt | xargs rm

	sysrepo-plugind
