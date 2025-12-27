project(
	'swaylock',
	'c',
	version: '1.7.0.0',
	license: 'MIT',
	meson_version: '>=0.59.0',
	default_options: [
		'c_std=c11',
		'warning_level=2',
		'werror=true',
	],
)

add_project_arguments(
	[
		'-Wno-unused-parameter',
		'-Wno-unused-result',
		'-Wundef',
		'-Wvla',
	],
	language: 'c',
)

cc = meson.get_compiler('c')

if get_option('sse')
	add_project_arguments('-DUSE_SSE', language: 'c')
endif

wayland_client = dependency('wayland-client', version: '>=1.20.0')
wayland_protos = dependency('wayland-protocols', version: '>=1.25', fallback: 'wayland-protocols')
wayland_scanner = dependency('wayland-scanner', version: '>=1.15.0', native: true)
xkbcommon = dependency('xkbcommon')
cairo = dependency('cairo')
omp = dependency('openmp')
gdk_pixbuf = dependency('gdk-pixbuf-2.0', required: get_option('gdk-pixbuf'))
libpam = cc.find_library('pam', required: get_option('pam'))
crypt = cc.find_library('crypt', required: not libpam.found())
math = cc.find_library('m')
rt = cc.find_library('rt')
dl = cc.find_library('dl')

wayland_scanner_prog = find_program(wayland_scanner.get_variable('wayland_scanner'), native: true)

version = meson.project_version()
wl_protocol_dir = wayland_protos.get_variable('pkgdatadir')

wayland_scanner_code = generator(
	wayland_scanner_prog,
	output: '@BASENAME@-protocol.c',
	arguments: ['private-code', '@INPUT@', '@OUTPUT@'],
)

wayland_scanner_client = generator(
	wayland_scanner_prog,
	output: '@BASENAME@-client-protocol.h',
	arguments: ['client-header', '@INPUT@', '@OUTPUT@'],
)

client_protocols = [
	wl_protocol_dir / 'stable/xdg-shell/xdg-shell.xml',
	wl_protocol_dir / 'staging/ext-session-lock/ext-session-lock-v1.xml',
	'wlr-layer-shell-unstable-v1.xml',
	'wlr-input-inhibitor-unstable-v1.xml',
	'wlr-screencopy-unstable-v1.xml',
]

protos_src = []
foreach xml : client_protocols
	protos_src += wayland_scanner_code.process(xml)
	protos_src += wayland_scanner_client.process(xml)
endforeach

conf_data = configuration_data()
conf_data.set_quoted('SYSCONFDIR', get_option('prefix') / get_option('sysconfdir'))
conf_data.set_quoted('SWAYLOCK_VERSION', version)
conf_data.set10('HAVE_GDK_PIXBUF', gdk_pixbuf.found())

subdir('include')

dependencies = [
	cairo,
	gdk_pixbuf,
	math,
	rt,
	dl,
	xkbcommon,
	wayland_client,
	omp
]

sources = [
	'background-image.c',
	'cairo.c',
	'comm.c',
	'log.c',
	'loop.c',
	'main.c',
	'password.c',
	'password-buffer.c',
	'pool-buffer.c',
	'render.c',
	'seat.c',
	'unicode.c',
	'effects.c',
	'fade.c',
]

if libpam.found()
	sources += ['pam.c']
	dependencies += [libpam]
else
	warning('The swaylock binary must be setuid when compiled without libpam')
	warning('You must do this manually post-install: chmod a+s /path/to/swaylock')
	sources += ['shadow.c']
	dependencies += [crypt]
endif

swaylock_inc = include_directories('include')

executable('swaylock',
	sources + protos_src,
	include_directories: [swaylock_inc],
	dependencies: dependencies,
	install: true
)

install_data(
	'pam/swaylock',
	install_dir: get_option('sysconfdir') / 'pam.d'
)
