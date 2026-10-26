# GTK4 + tray — digest (Pass 2, verified live on this machine)

Raw: gtk/gtk4-tray-thread.html (discourse) + vendor typelib probes.

- GTK4 4.18 is installed (gir1.2-gtk-4.0). Gtk.StatusIcon REMOVED in GTK4;
  libayatana-appindicator3 is a GTK3 binding → DON'T mix toolkits in one
  process.
- BUILT (verified against the real watcher): tray = **DBus
  StatusNotifierItem via Gio only** (org.kde.StatusNotifierItem + canonical
  dbusmenu); PyGObject closures must call invocation.return_value() or the
  client times out; ToolTip wire type is (sa(iiay)ss) — the SNI spec page's
  "(iiays)" is a typo.
- Degradation: every bus call guarded — without a watcher the app opens
  windowless with a note (tested).
- RAM: GL/Vulkan init maps ~75 MB of Mesa — GDK_DISABLE=gl:vulkan keeps the
  dashboard at ~130 MB idle (< the app's 150 MB cap). Reversible in app.py.
- libadwaita 1.7 available but NOT adopted (flagged D4 — bigger rewrite;
  owner decision).