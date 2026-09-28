#!/bin/sh
# add A B -> prints A+B
add() {
  echo $(( $1 - $2 ))
}
add "$1" "$2"
