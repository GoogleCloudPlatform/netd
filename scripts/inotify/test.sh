#!/bin/sh

if [ -n "$1" ]; then
  printf . >>"$INOTIFY_TEST_CALL"
  "$@"
  exit
fi

INOTIFY=./inotify
INOTIFY_TIMEOUT=2000

xsleep() {
  sleep "$(echo "scale = 3; $1 * $INOTIFY_TIMEOUT / 1000" | bc)s"
}

xtimeout() {
  time=$1; shift
  timeout "$(echo "scale = 3; $time * $INOTIFY_TIMEOUT / 1000" | bc)s" "$@"
}

echo "TESTING INOTIFY: $INOTIFY"
FAIL_COUNT=0

begin() {
  INOTIFY_TEST_NAME=$1
  INOTIFY_TEST_CALL=$(mktemp)
  INOTIFY_TEST_FOO=$(mktemp -d)
  INOTIFY_TEST_BAR=$(mktemp -d)
  export INOTIFY_TEST_NAME
  export INOTIFY_TEST_CALL
  export INOTIFY_TEST_FOO
  export INOTIFY_TEST_BAR
  echo "== Test $INOTIFY_TEST_NAME in $INOTIFY_TEST_FOO and $INOTIFY_TEST_BAR using $INOTIFY_TEST_CALL"
}

end() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "** FAIL with exit status $status"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi
  calls=$(wc -c "$INOTIFY_TEST_CALL" | cut -d' ' -f1)
  if [ "$1" -eq "$calls" ]; then
    echo "-- Pass with $calls callbacks"
  else
    echo "** FAIL with $calls callbacks; expected: $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

set -u

begin initial
xtimeout 0.5 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" true
end 1

begin after_timeout
( xsleep 1.5; touch "$INOTIFY_TEST_BAR/file" ) &
xtimeout 2.5 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_BAR/file" ]
end 3

begin after_event
( xsleep 0.5; touch "$INOTIFY_TEST_FOO/file" ) &
xtimeout 1 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_FOO/file" ]
end 2

begin after_event_before_timeout
( xsleep 0.5; touch "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.25; touch "$INOTIFY_TEST_BAR/file" ) &
xtimeout 1 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_FOO/file" -a ! -f "$INOTIFY_TEST_BAR/file" ]
end 2

begin after_timeout_then_event
( xsleep 1.5; touch "$INOTIFY_TEST_FOO/file" ) &
xtimeout 2 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_FOO/file" ]
end 3

begin after_timeout_then_event_before_next_timeout
( xsleep 1.5; touch "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.25; touch "$INOTIFY_TEST_BAR/file" ) &
xtimeout 2 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_FOO/file" -a ! -f "$INOTIFY_TEST_BAR/file" ]
end 3

begin after_nonmatching_then_timeout
( xsleep 0.5; touch "$INOTIFY_TEST_BAR/file" "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.5; rm "$INOTIFY_TEST_BAR/file" ) &
xtimeout 2 "$INOTIFY" "$INOTIFY_TEST_FOO" file "$0" [ -f "$INOTIFY_TEST_FOO/other" -a ! -f "$INOTIFY_TEST_BAR/file" ]
end 2

begin after_nonmatching_then_event_before_next_timeout
( xsleep 0.25; touch "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.25; touch "$INOTIFY_TEST_BAR/file" ) &
xtimeout 1 "$INOTIFY" "$INOTIFY_TEST_FOO" file "$0" [ -f "$INOTIFY_TEST_FOO/file" -a ! -f "$INOTIFY_TEST_BAR/file" ]
end 2

begin after_timeout_from_nonmatching
( xsleep 0.25; touch "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/other" "$INOTIFY_TEST_BAR/file"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.25; touch "$INOTIFY_TEST_FOO/other" ) &
xtimeout 1.5 "$INOTIFY" "$INOTIFY_TEST_FOO" file "$0" [ -f "$INOTIFY_TEST_BAR/file" ]
end 2

begin after_timeout_then_nonmatching_then_timeout
( xsleep 1.5; touch "$INOTIFY_TEST_BAR/file" "$INOTIFY_TEST_FOO/other"; \
  xsleep 0.5; rm "$INOTIFY_TEST_BAR/file" ) &
xtimeout 3 "$INOTIFY" "$INOTIFY_TEST_FOO" file "$0" [ -f "$INOTIFY_TEST_FOO/other" -a ! -f "$INOTIFY_TEST_BAR/file" ]
end 3

begin retry_callback_for_timeouts
( xsleep 1.5; touch "$INOTIFY_TEST_BAR/file" ) &
xtimeout 2.5 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_BAR/file" ]
end 3

begin retry_callback_for_events_before_next_timeout
( xsleep 0.5; touch "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.5; touch "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.5; touch "$INOTIFY_TEST_BAR/file" "$INOTIFY_TEST_FOO/file"; \
  xsleep 0.25; rm "$INOTIFY_TEST_BAR/file" ) &
xtimeout 2 "$INOTIFY" "$INOTIFY_TEST_FOO" '' "$0" [ -f "$INOTIFY_TEST_BAR/file" ]
end 4

exit $FAIL_COUNT
