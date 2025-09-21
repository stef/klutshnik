#!/sbin/openrc-run
# shellcheck shell=ash

depend() {
  need localmount
  need networking
}

start() {
	klutshnik-setup
}
