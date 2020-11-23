cowmail_server_sources = [
  'main.c',
]

cowmail_server_deps = [
  dependency('gio-2.0'),
  dependency('nettle', version: '>= 3.6'),
]

cowmail_test_sources = [
  'tests.c',
]

cowmail_test_deps = [
  dependency('gio-2.0'),
  dependency('nettle', version: '>= 3.6'),
]

executable('cowmail-server', cowmail_server_sources,
  dependencies: cowmail_server_deps,
  install: true,
)

executable('cowmail-tests', cowmail_test_sources,
  dependencies: cowmail_test_deps,
  install: false,
)
