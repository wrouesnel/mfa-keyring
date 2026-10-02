cmocka = dependency('cmocka', required : false)

if cmocka.found()
  test('core', executable('test_core', 'test_core.c',
    dependencies : [core_dep, cmocka]),
    timeout : 120)
endif

pamtest = executable('pamtest', 'pamtest.c', dependencies : [libpam])

test('integration', find_program('integration.sh'),
  args : [meson.project_build_root(), meson.project_source_root()],
  depends : [pamtest],
  timeout : 600,
  is_parallel : false)
