#!/sbin/openrc-run
# shellcheck shell=ash
# shellcheck disable=SC2034

command="/usr/bin/sbox.sh"
command_args="/usr/bin/klutshnikd /etc/klutshnik/config /etc/klutshnik/klutshnikd.bpf"
pidfile="/var/run/klutshnikd.pid"
command_background=true
command_user="klutshnik:klutshnik"
output_log="/data/klutshnik/log"
error_log="/data/klutshnik/err"

depend() {
  use logger
  need net
  need klutshnik-setup
}
