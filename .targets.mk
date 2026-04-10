# draft-hardt-aauth-headers draft-hardt-aauth-protocol draft-hardt-aauth-r3 
# draft-hardt-aauth-headers-00 draft-hardt-aauth-protocol-00
versioned:
	@mkdir -p $@
.INTERMEDIATE: versioned/draft-hardt-aauth-headers-00.md
.SECONDARY: versioned/draft-hardt-aauth-headers-00.xml
versioned/draft-hardt-aauth-headers-00.md: | versioned
	git show "draft-hardt-aauth-headers-00:draft-hardt-aauth-headers.md" | sed -e 's/draft-hardt-aauth-headers-date/2026-04-02/g' -e 's/draft-hardt-aauth-headers-latest/draft-hardt-aauth-headers-00/g' -e 's/draft-hardt-aauth-mission-date/2026-04-04/g' -e 's/draft-hardt-aauth-mission-latest/draft-hardt-aauth-mission-00/g' -e 's/draft-hardt-aauth-protocol-date/2026-04-02/g' -e 's/draft-hardt-aauth-protocol-latest/draft-hardt-aauth-protocol-00/g' -e 's/draft-hardt-aauth-r3-date/2026-04-04/g' -e 's/draft-hardt-aauth-r3-latest/draft-hardt-aauth-r3-00/g' -e 's/draft-hardt-aauth.archive-date/2026-04-04/g' -e 's/draft-hardt-aauth.archive-latest/draft-hardt-aauth.archive-00/g' -e '/^{::include [^\/]/{ s/^{::include /{::include versioned\/draft-hardt-aauth-headers-00\//; }' >$@
	$(LIBDIR)/make-includes.sh "draft-hardt-aauth-headers-00" "draft-hardt-aauth-headers-00" "$@"
.INTERMEDIATE: versioned/draft-hardt-aauth-headers-01.md
versioned/draft-hardt-aauth-headers-01.md: draft-hardt-aauth-headers.md | versioned
	sed -e 's/draft-hardt-aauth-headers-date/2026-04-04/g' -e 's/draft-hardt-aauth-headers-latest/draft-hardt-aauth-headers-01/g' -e 's/draft-hardt-aauth-mission-date/2026-04-04/g' -e 's/draft-hardt-aauth-mission-latest/draft-hardt-aauth-mission-00/g' -e 's/draft-hardt-aauth-protocol-date/2026-04-04/g' -e 's/draft-hardt-aauth-protocol-latest/draft-hardt-aauth-protocol-01/g' -e 's/draft-hardt-aauth-r3-date/2026-04-04/g' -e 's/draft-hardt-aauth-r3-latest/draft-hardt-aauth-r3-00/g' -e '/^{::include [^\/]/{ s/^{::include /{::include versioned\/draft-hardt-aauth-headers-01\//; }' $< >$@
	$(LIBDIR)/make-includes.sh "HEAD" "draft-hardt-aauth-headers-01" "$@"
diff-draft-hardt-aauth-headers.html: versioned/draft-hardt-aauth-headers-00.txt versioned/draft-hardt-aauth-headers-01.txt
	-$(iddiff) $^ > $@
.INTERMEDIATE: versioned/draft-hardt-aauth-protocol-00.md
.SECONDARY: versioned/draft-hardt-aauth-protocol-00.xml
versioned/draft-hardt-aauth-protocol-00.md: | versioned
	git show "draft-hardt-aauth-protocol-00:draft-hardt-aauth-protocol.md" | sed -e 's/draft-hardt-aauth-headers-date/2026-04-02/g' -e 's/draft-hardt-aauth-headers-latest/draft-hardt-aauth-headers-00/g' -e 's/draft-hardt-aauth-mission-date/2026-04-04/g' -e 's/draft-hardt-aauth-mission-latest/draft-hardt-aauth-mission-00/g' -e 's/draft-hardt-aauth-protocol-date/2026-04-02/g' -e 's/draft-hardt-aauth-protocol-latest/draft-hardt-aauth-protocol-00/g' -e 's/draft-hardt-aauth-r3-date/2026-04-04/g' -e 's/draft-hardt-aauth-r3-latest/draft-hardt-aauth-r3-00/g' -e 's/draft-hardt-aauth.archive-date/2026-04-04/g' -e 's/draft-hardt-aauth.archive-latest/draft-hardt-aauth.archive-00/g' -e '/^{::include [^\/]/{ s/^{::include /{::include versioned\/draft-hardt-aauth-protocol-00\//; }' >$@
	$(LIBDIR)/make-includes.sh "draft-hardt-aauth-protocol-00" "draft-hardt-aauth-protocol-00" "$@"
.INTERMEDIATE: versioned/draft-hardt-aauth-protocol-01.md
versioned/draft-hardt-aauth-protocol-01.md: draft-hardt-aauth-protocol.md | versioned
	sed -e 's/draft-hardt-aauth-headers-date/2026-04-04/g' -e 's/draft-hardt-aauth-headers-latest/draft-hardt-aauth-headers-01/g' -e 's/draft-hardt-aauth-mission-date/2026-04-04/g' -e 's/draft-hardt-aauth-mission-latest/draft-hardt-aauth-mission-00/g' -e 's/draft-hardt-aauth-protocol-date/2026-04-04/g' -e 's/draft-hardt-aauth-protocol-latest/draft-hardt-aauth-protocol-01/g' -e 's/draft-hardt-aauth-r3-date/2026-04-04/g' -e 's/draft-hardt-aauth-r3-latest/draft-hardt-aauth-r3-00/g' -e '/^{::include [^\/]/{ s/^{::include /{::include versioned\/draft-hardt-aauth-protocol-01\//; }' $< >$@
	$(LIBDIR)/make-includes.sh "HEAD" "draft-hardt-aauth-protocol-01" "$@"
diff-draft-hardt-aauth-protocol.html: versioned/draft-hardt-aauth-protocol-00.txt versioned/draft-hardt-aauth-protocol-01.txt
	-$(iddiff) $^ > $@
.INTERMEDIATE: versioned/draft-hardt-aauth-r3-00.md
versioned/draft-hardt-aauth-r3-00.md: draft-hardt-aauth-r3.md | versioned
	sed -e 's/draft-hardt-aauth-headers-date/2026-04-04/g' -e 's/draft-hardt-aauth-headers-latest/draft-hardt-aauth-headers-01/g' -e 's/draft-hardt-aauth-mission-date/2026-04-04/g' -e 's/draft-hardt-aauth-mission-latest/draft-hardt-aauth-mission-00/g' -e 's/draft-hardt-aauth-protocol-date/2026-04-04/g' -e 's/draft-hardt-aauth-protocol-latest/draft-hardt-aauth-protocol-01/g' -e 's/draft-hardt-aauth-r3-date/2026-04-04/g' -e 's/draft-hardt-aauth-r3-latest/draft-hardt-aauth-r3-00/g' -e '/^{::include [^\/]/{ s/^{::include /{::include versioned\/draft-hardt-aauth-r3-00\//; }' $< >$@
	$(LIBDIR)/make-includes.sh "HEAD" "draft-hardt-aauth-r3-00" "$@"
