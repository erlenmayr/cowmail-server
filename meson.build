project('cowmail-server', 'c',
          version: '0.2.0',
    meson_version: '>= 0.49.0',
  default_options: [ 'warning_level=2',
                     'c_std=gnu11',
                   ],
)


config_h = configuration_data()
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
  output: 'cowmail_server-config.h',
  configuration: config_h,
)
add_project_arguments([
  '-I' + meson.build_root(),
], language: 'c')

subdir('src')
