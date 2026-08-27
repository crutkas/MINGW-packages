" Preserve Git for Windows' POSIX shell behavior in the native Win32 build.
if exists('$SHELL') && executable($SHELL)
  let &shell = $SHELL
elseif executable(expand('$VIM') . '/sh.exe')
  let &shell = expand('$VIM') . '/sh.exe'
endif

if &shell =~? '\v(^|[/\\])(ba|z|da|k)?sh(\.exe)?$'
  set shellcmdflag=-c
  set shellquote=
  set shellxquote=\"
  set shellslash
  set shellredir=>%s\ 2>&1
  set shellpipe=2>&1\|\ tee
endif
