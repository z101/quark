#!/usr/local/plan9/bin/rc

# quark debug script

name=quark

qpids=`{ pidof $name }
if (! ~ $#qpids 0) {
	echo [ERROR] quark process already running
	exit 1
}

make clean; rm -f config.h
make

opts_chrootdir=/
opts_cgidir=/home/z101/repos/swerc/bin
opts_cgiscript=./werc.rc
opts_user=www-data
opts_group=www-data
opts_server=93.189.43.88

daemon=./$name
daemon_opts=(-c -C $"opts_chrootdir -d $"opts_cgidir -e $"opts_cgiscript -u $"opts_user -g $"opts_group -s $"opts_server)
daemon_cmd=($"daemon $"daemon_opts '>[2=1]')

echo
echo ---------------------------
echo

eval $"daemon_cmd
