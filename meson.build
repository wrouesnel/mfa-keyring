project('mfa-keyring', 'c',
  version : '0.1.0',
  license : 'GPL-2.0-or-later',
  meson_version : '>= 0.60',
  default_options : ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

cc = meson.get_compiler('c')

add_project_arguments(
  '-D_GNU_SOURCE',
  '-fvisibility=hidden',
  '-Wno-unused-parameter',
  '-Wformat=2',
  '-Wshadow',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  language : 'c')

libsodium = dependency('libsodium')
libcrypto = dependency('libcrypto', version : '>= 3.0')
p11kit = dependency('p11-kit-1')        # headers only (<p11-kit/pkcs11.h>)
libdl = cc.find_library('dl', required : false)
libpam = cc.find_library('pam')
glib = dependency('gio-2.0', required : get_option('cli'))
libfido2 = dependency('libfido2', version : '>= 1.10', required : get_option('fido2'))

p11kit_headers = p11kit.partial_dependency(compile_args : true, includes : true)

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('DEFAULT_PKCS11_MODULE', get_option('default_pkcs11_module'))
conf.set_quoted('DEFAULT_WRAP_FILE', '%h/.local/share/mfa-keyring/login.wrap')
conf.set10('HAVE_FIDO2', libfido2.found())
configure_file(output : 'config.h', configuration : conf)

core_src = files(
  'src/util.c',
  'src/wrapfile.c',
  'src/crypt.c',
  'src/p11.c',
  'src/fido2.c',
  'src/slots.c',
)

core_deps = [libsodium, libcrypto, p11kit_headers, libdl]
if libfido2.found()
  core_deps += libfido2
endif

core = static_library('mfakr-core', core_src,
  dependencies : core_deps,
  pic : true,
  include_directories : include_directories('.', 'src'))

core_dep = declare_dependency(link_with : core,
  dependencies : core_deps,
  include_directories : include_directories('.', 'src'))

pamdir = get_option('pamlibdir')
if pamdir == ''
  pamdir = get_option('libdir') / 'security'
endif

shared_module('pam_mfa_keyring', 'src/pam_mfa_keyring.c',
  name_prefix : '',
  dependencies : [core_dep, libpam],
  link_args : ['-Wl,--version-script=' + meson.current_source_dir() / 'src/pam_mfa_keyring.map',
               '-Wl,-z,relro,-z,now', '-Wl,--no-undefined'],
  link_depends : 'src/pam_mfa_keyring.map',
  install : true,
  install_dir : pamdir)

if glib.found()
  executable('mfa-keyring', 'src/mfa-keyring.c', 'src/gkr.c',
    dependencies : [core_dep, glib],
    install : true)
endif

install_data('pam/pam-configs/mfa-keyring',
  install_dir : get_option('datadir') / 'pam-configs')
install_data('pam/gdm-smartcard-sssd-mfa-keyring',
  install_dir : get_option('sysconfdir') / 'pam.d')
install_man('man/pam_mfa_keyring.8', 'man/mfa-keyring.1')

if get_option('tests')
  subdir('tests')
endif
