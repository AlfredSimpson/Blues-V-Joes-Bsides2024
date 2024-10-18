#!/bin/sh
# -*- Shell-script -*-

# $Id: chkrootkit, v 0.58b 2023/07/05
CHKROOTKIT_VERSION='0.58b'

# Authors: Nelson Murilo <nmurilo@gmail.com> (main author) and
#          Klaus Steding-Jessen <jessen@cert.br>
#
# (c)1997-2023 Nelson Murilo, AMS Foundation and others.
# All rights reserved

### workaround for some Bourne shell implementations
unalias login > /dev/null 2>&1
unalias ls > /dev/null 2>&1
unalias netstat > /dev/null 2>&1
unalias ss > /dev/null 2>&1
unalias ps > /dev/null 2>&1
unalias dirname > /dev/null 2>&1

cd /usr/lib/chkrootkit 2>/dev/null || echo "Could not cd /usr/lib/chkrootkit/"

# Workaround for recent GNU coreutils
_POSIX2_VERSION=199209
export _POSIX2_VERSION

KALLSYMS="/proc/kallsyms"
[ -f /proc/ksysm ] && KALLSYMS="/proc/$KALLSYMS"

# Native commands
TROJAN="amd basename biff chfn chsh cron crontab date du dirname echo egrep \
env find fingerd gpm grep hdparm su ifconfig inetd inetdconf identd init \
killall ldsopreload login ls lsof mail mingetty netstat named passwd pidof \
pop2 pop3 ps pstree rpcinfo rlogind rshd slogin sendmail sshd syslogd tar tcpd \
tcpdump top telnetd timed traceroute vdir w write"

# Tools
TOOLS="aliens asp bindshell lkm rexedcs sniffer w55808 wted scalper slapper z2 chkutmp OSX_RSPLUG"

# Return Codes
INFECTED=0
NOT_INFECTED=1
NOT_TESTED=2
NOT_FOUND=3
INFECTED_BUT_DISABLED=4

# Many trojaned commands have this label
GENERIC_ROOTKIT_LABEL="^/bin/.*sh$|bash|elite$|vejeta|\.ark|iroffer"

######################################################################
# tools functions

#
# 55808.A Worm
#
w55808 (){
   W55808_FILES="${ROOTDIR}tmp/.../a ${ROOTDIR}tmp/.../r"
   STATUS=0

   for i in ${W55808_FILES}; do
      if [ -f "${i}" ]; then
          STATUS=1
      fi
   done
   if [ "${STATUS}" -eq 1 ] ;then
      _warn "Possible 55808 Worm installed\n"
   else
      _not_found
      return "${NOT_INFECTED}"
   fi
}

OSX_RSPLUG (){
    if [ "${SYSTEM}" != "Darwin" ]; then
        if [ "${QUIET}" != "t" ]; then echo "not tested"; fi
        return
    fi
    SAVEIFS=$IFS
    IFS=';'
    STATUS=0
    OSX_RSPLUG_FILES='/Library/Internet Plug-Ins/QuickTime.xpt;/Library/Internet Plug-Ins/plugins.settings'
#       echo checking ${OSX_RSPLUG_FILES}
    for i in ${OSX_RSPLUG_FILES} ; do
        echo searching for "${i}"
        if [ -e "${i}" ] ; then
            STATUS=1
        fi
    done
    IFS=$SAVEIFS

   if [ "${STATUS}" -eq 1 ] ;then
      echo "Warning: OSX.RSPlug.A Trojan Horse found"
      return "${INFECTED}"
   else
       if [ "${QUIET}" != "t" ]; then echo "not infected"; fi
       return "${NOT_INFECTED}"
   fi
}

#
# SLAPPER.{A,B,C,D} and the multi-platform variant
#
slapper (){
   SLAPPER_FILES="${ROOTDIR}tmp/.bugtraq ${ROOTDIR}tmp/.bugtraq.c"
   SLAPPER_FILES="$SLAPPER_FILES ${ROOTDIR}tmp/.unlock ${ROOTDIR}tmp/httpd \
   ${ROOTDIR}tmp/update ${ROOTDIR}tmp/.cinik ${ROOTDIR}tmp/.b"
   SLAPPER_PORT="0.0:2002 |0.0:4156 |0.0:1978 |0.0:1812 |0.0:2015 "
   _chk_netstat_or_ss;
   OPT="-an"
   STATUS=0
   file_port=""

   if ${netstat} "${OPT}" 2>/dev/null | ${egrep} -q "^tcp.+${SLAPPER_PORT}"; then
      STATUS=1
      if [ "$SYSTEM" = "Linux" ]; then
           file_port=$(${netstat} -p "${OPT}" | \
                $egrep ^tcp|$egrep "${SLAPPER_PORT}" | "${awk}" '{ print  $7 }' | tr -d :)
      fi
   fi
   for i in ${SLAPPER_FILES}; do
       if [ -f "${i}" ]; then
           file_port=$(_filter "$i" "$file_port")
           STATUS=1
       fi
   done
   if [ "${STATUS}" -eq 1 ] ;then
      _warn "Possible Slapper Worm installed:\n$file_port\n"
   else
      _not_found
   fi
}

scalper (){
   SCALPER_FILES="${ROOTDIR}tmp/.uua ${ROOTDIR}tmp/.a"
   SCALPER_PORT=2001
   OPT="-an"
   _chk_netstat_or_ss;
   STATUS=0

   if ${netstat} "${OPT}" 2>/dev/null | ${egrep} -q "0.0:${SCALPER_PORT}"; then
      if ! [ -e /usr/sbin/ser2net ]; then
        STATUS=1
      fi
   fi
   for i in ${SCALPER_FILES}; do
      if [ -f "${i}" ]; then
         STATUS=1
      fi
   done
   if [ "${STATUS}" -eq 1 ] ;then
       _warn "Possible Scalper Worm installed\n"
       return "${INFECTED}"
   else
      _not_found
      return "${NOT_INFECTED}"
   fi
}

asp (){
    ASP_LABEL="poop"
    STATUS=${NOT_INFECTED}
    CMD=$(loc asp asp "$pth")

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${egrep} ^asp ${ROOTDIR}etc/inetd.conf"
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if ${egrep} "^asp" "${ROOTDIR}etc/inetd.conf" >/dev/null 2>&1; then
        _warn "Possible Ramen Worm installed in ${ROOTDIR}etc/inetd.conf\n"
        STATUS=${INFECTED}
    fi
    if [ "${CMD}" = "asp" ] || [ "${CMD}" = "${ROOTDIR}asp" ]; then
        if [ "${QUIET}" != "t" ]; then echo "not infected"; fi
        return "${NOT_INFECTED}"
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${ASP_LABEL}" >/dev/null 2>&1; then
       # echo "INFECTED"
       STATUS=${INFECTED}
    else
        if [ "${QUIET}" != "t" ]; then echo "not infected"; fi
        return "${NOT_INFECTED}"
    fi
    return "${STATUS}"
}

sniffer () {
    if [ "${ROOTDIR}" != "/" ]; then
		_not_tested
		return "${NOT_TESTED}"
    fi

    if [ "$SYSTEM" = "SunOS" ]; then
		_not_tested
		return "${NOT_TESTED}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "./ifpromisc" -v
        return 5
    fi
    if [ ! -x ./ifpromisc ]; then
        _warn "sniffer not tested: can't exec ./ifpromisc"
        return "${NOT_TESTED}"
    else
		status=0
		if [ "${QUIET}" != "t" ]; then
			outmsg=$(./ifpromisc -v 2>&1)
			status=$?
		else
			outmsg=$(./ifpromisc -q 2>&1)
			status=$?
		fi
		if [ "$status" = 0 ]; then
			_not_found
		else
			if [ -n "$EXCLUDES_SNIF" ]; then
				outmsg=$(echo "$outmsg" | ${egrep} -v "$EXCLUDES_SNIF")
			fi
			_report "Output from ifpromisc" "$outmsg"
		fi
    fi
}

chkutmp() {
    if [ "${mode}" = "pm" ]; then
		_not_tested
        return "${NOT_TESTED}"
    fi
    if [ "$SYSTEM" = "Linux" ] && [ ! -f /var/run/utmp ]; then
        # utmp was rewritten incompatibly to make time_t 64-bit
        _not_tested
        return "${NOT_TESTED}"
    fi
    if [ ! -x ./chkutmp ]; then
        _warn "chkutmp not tested: can't exec ./chkutmp"
        return "${NOT_TESTED}"
    fi
    outmsg=$(PATH="$path_for_tools" ./chkutmp 2>&1)
    if [ $? -eq 0 ]; then
        _not_found
    else
        _warn "chkutmp output: $outmsg\n"
    fi
}

z2 () {
    if [ ! -x ./chklastlog ]; then
      _warn "z2 not tested: can't exec ./chklastlog"
      return "${NOT_TESTED}"
    fi

    WTMP=$(loc wtmp wtmp "${ROOTDIR}var/log ${ROOTDIR}var/adm")
    LASTLOG=$(loc lastlog lastlog "${ROOTDIR}var/log ${ROOTDIR}var/adm")

    if [ ! -f "$WTMP" ] && [ ! -f "$LASTLOG" ]; then
        _not_tested
        return "${NOT_TESTED}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "./chklastlog ${QUIET_ARG} -f ${ROOTDIR}${WTMP} -l ${ROOTDIR}${LASTLOG}"
        return 5
    fi

    outmsg=$(./chklastlog "${QUIET_ARG}" -f "${WTMP}" -l "${LASTLOG}" 2>&1)
    if [ $? -eq 0 ]; then
        _not_found
    else
        _warn "output from chklastlog:\n$outmsg\n"
    fi
}

wted () {
    if [ ! -x ./chkwtmp ]; then
        _warn "wted not tested: can't exec ./chkwtmp"
        return "${NOT_TESTED}"
    fi

    if [ "$SYSTEM" = "SunOS" ]; then
        if [ ! -x ./check_wtmpx ]; then
            _warn "wted not tested: can't exec ./check_wtmpx"
        else
            if [ "${EXPERT}" = "t" ]; then
                expertmode_output "./check_wtmpx"
                return 5
            fi
            if [ -f "${ROOTDIR}var/adm/wtmp" ]; then
                if ./check_wtmpx
                then
                    if [ "${QUIET}" != "t" ]; then \
                        echo "check_wtmpx: nothing deleted in /var/adm/wtmpx"; fi
                fi
            fi
        fi
    else
        WTMP=""
        for f in "${ROOTDIR}var/log/wtmp" "${ROOTDIR}var/adm"; do
            if [ -f "$f" ]; then
                WTMP="$f"
                break
            fi
        done
        if [ "$SYSTEM" = "Linux" ] && [ -z "$WTMP" ]; then
            # wtmp was rewritten incompatibly to make time_t 64-bit
            _not_tested
            return "${NOT_TESTED}"
        fi


        if [ "${EXPERT}" = "t" ]; then
            expertmode_output "./chkwtmp -f ${WTMP}"
            return 5
        fi

        if outmsg=$(./chkwtmp -f "${WTMP}" 2>&1); then
            _not_found
        else
            _warn "output from chkwtmp:\n$outmsg\n"
        fi
    fi
}

bindshell () {
PORT="114 145 465 511 600 1008 1524 1999 1978 2881 3049 3133 3879 4000 4369 5190 5665 6667 10008 12321 23132 27374 29364 30999 31336 31337 37998 45454 47017 47889 60001 7222"
   OPT="-an"
   _chk_netstat_or_ss;
   PI=""
   if [ "${ROOTDIR}" != "/" ]; then
     _not_tested
     return "${NOT_TESTED}"
   fi

   if [ "${EXPERT}" = "t" ]; then
       expertmode_output "${netstat} ${OPT}"
       return 5
   fi
   for P in $PORT; do
       if ${netstat} "${OPT}" 2>/dev/null | ${egrep} -q "^(tcp.*LIST|udp).*[.:]${P}[^0-9.:]"
      then
         PI="${PI} ${P}"
      fi
   done
   if [ -n "${PI}" ]; then
       _warn "Potential bindshell installed: infected ports:$PI\n"
   else
       _not_found
   fi
}

lkm (){
    if [ "${EXPERT}" = "t" ]; then
        [ -r "/proc/$KALLSYMS" ] &&  ${egrep} -i "adore|sebek" < "/proc/$KALLSYMS" 2>/dev/null
        [ -d /proc/knark ] &&  "${ls}" -la /proc/knark 2> /dev/null
        PV=$("${ps}" -V 2>/dev/null| "${cut}" -d " " -f 3 |"${awk}" -F . '{ print $1 "." $2 $3 }' | "${awk}" '{ if ($0 > 3.19) print 3; else if ($0 < 2.015) print 1; else print 2 }')
        [ "$PV" = "" ] &&  PV=2
        [ "${SYSTEM}" = "SunOS" ] && PV=0
        expertmode_output "./chkproc -v -v -p $PV"
        return 5
    fi
    [ "$QUIET" != "t" ] && echo "started"
    _start "Adore LKM"
    if [ -r "/proc/$KALLSYMS" ]; then
        if ${egrep} -i adore < "/proc/$KALLSYMS" >/dev/null 2>&1; then
            _warn "Adore LKM installed\n"
        else
            _not_found
        fi
    else
        _not_tested
    fi

    _start "sebek LKM (Adore based)"
    if [ -r "/proc/$KALLSYMS" ]; then
        if ${egrep} -i sebek < "/proc/$KALLSYMS" >/dev/null 2>&1; then
            _warn "Sebek LKM installed\n"
        else
            _not_found
        fi
    else
        _not_tested
    fi

    lookfor_rootkit "knark LKM" "" "/proc/knark"

    prog=""
    _start "for hidden processes with chkproc"
    if [ ! -x ./chkproc ]; then
        _warn "chkproc not tested: can't exec ./chkproc"
    elif [ "${mode}" != rt ]; then
        _not_tested
    else
        if [ "$SYSTEM" = "Linux" ]; then
            F=$($ps -V 2>/dev/null | wc -w)
            PV=$($ps -V 2>/dev/null| $cut -d " " -f "$F" | "${awk}" -F . '{ print $1 "." $2 $3 }' | "${awk}" '{ if ($0 > 3.19) print 3; else if ($0 < 2.11) print 1; else print 2 }')
        fi
        [ "$PV" = "" ] &&  PV=2
        [ "${SYSTEM}" = "SunOS" ] && PV=0
        if [ "${DEBUG}" = "t" ]; then
            echo "*** PV=$PV ***"
        fi

        if files=$(PATH="$path_for_tools" ./chkproc -p "${PV}" 2>&1); then
            _not_found
        else
            _report "chkproc: Possible LKM Trojan installed (or chkproc failed)" "$files"
        fi
    fi

    _start "for hidden directories using chkdirs"
    if [ ! -x ./chkdirs ]; then
        _warn "chkdirs not tested: can't exec chkdirs"
    else
        dirs=""
        for i in tmp usr/share usr/bin usr/sbin lib usr/lib; do
            if [ -d "${ROOTDIR}$i" ]; then
                dirs="$dirs ${ROOTDIR}$i"
            fi
        done
        if [ -z "$dirs" ]; then
            _not_tested
        elif files=$(./chkdirs $dirs 2>&1); then
            _not_found
        else
            _report "chkdirs: Possible LKM Trojan installed (or chkdirs failed)" "$files"
        fi
    fi

    [ "$QUIET" != "t" ] && printn "Checking \`lkm'..."
    [ "$QUIET" != "t" ] && echo "finished"
}

_start(){
		if [ "${QUIET}" != "t" ]; then \
				printn "Searching for ${1}... "
		fi
}

_warn(){
		if [ "${QUIET}" != "t" ]; then
				# Finish the "checking ..." line
				echo "WARNING"
				# blank line before output
				echo
		fi
		# One line only in quiet mode
		printf "WARNING: %b\n" "$1"
}

_not_found(){
		if [ "${QUIET}" != "t" ]; then
				echo "not found"
		fi
}

# $1 is a message ("possible rootkit"), $2 a list of suspect files found (or empty)
_report(){
		if [ -n "$2" ]; then
				_warn "$1:\n$2\n"
		else
				_not_found
		fi
}

_not_tested(){
		if [ "${QUIET}" != "t" ]; then
				echo "not tested"
		fi
}

aliens () {
   if [ \( -z "${HOME}" -o "${HOME}" = "/" \) -a "$("${id}" -u)" = "0" -a -d "${ROOTDIR}root" ]; then
     HOME="${ROOTDIR}root"
   else
       # HOME is set
       case "$HOME" in
           "$ROOTDIR"*) ;; # eg no -r and /root
           /*) HOME="${ROOTDIR}${HOME#/}" ;; # -r /mnt and /root -> /mnt/root
           *) HOME="${ROOTDIR}${HOME}" ;; # unlikely : HOME is relative
       esac
   fi
   if [ "${EXPERT}" = "t" ]; then
        ### suspicious files
        FILES="usr/bin/sourcemask usr/bin/ras2xm usr/sbin/in.telnet \
sbin/vobiscum  usr/sbin/jcd usr/sbin/atd2 usr/bin/.etc usr/bin/xstat \
 etc/ld.so.hash"

        expertmode_output "${find} ${ROOTDIR}dev -type f"
        expertmode_output "${find} ${ROOTDIR}var/run/.tmp"
        expertmode_output "${find} ${ROOTDIR}usr/man/man1/lib/.lib"
        expertmode_output "${find} ${ROOTDIR}usr/man/man2/.man8"
        expertmode_output "${find} ${ROOTDIR}usr/man/man1 -name '.. *'"
        expertmode_output "${find} ${ROOTDIR}usr/share/locale/sk"
        expertmode_output "${find} ${ROOTDIR}usr/lib/dy0"
        expertmode_output "${find} ${ROOTDIR}tmp -name 982235016-gtkrc-429249277"
        expertmode_output "${find} ${ROOTDIR}var/spool/lp/admins/.lp/"

        for i in ${FILES}; do
           expertmode_output "${ls} ${ROOTDIR}${i} 2> /dev/null"
        done
        [ -d "${ROOTDIR}lib/.so" ] && expertmode_output "${find} ${ROOTDIR}lib/.so"
        [ -d "${ROOTDIR}usr/include/.. " ] && expertmode_output "${find} '${ROOTDIR}usr/include/.. '"
        [ -d "${ROOTDIR}usr/lib/.fx" ] && expertmode_output "${find} ${ROOTDIR}usr/lib/.fx"
        [ -d "${ROOTDIR}var/local/.lpd" ] && expertmode_output "${find} ${ROOTDIR}var/local/.lpd"
        [ -d "${ROOTDIR}dev/rd/cdb" ] && expertmode_output "${find} ${ROOTDIR}dev/rd/cdb"
        [ -d "${ROOTDIR}usr/lib/lib.so1.so" ] && expertmode_output "${find} ${ROOTDIR}usr/lib/lib.so1.so"
        ### sniffer's logs
        expertmode_output "${find} ${ROOTDIR}dev ${ROOTDIR}usr ${ROOTDIR}tmp \
	${ROOTDIR}lib ${ROOTDIR}etc ${ROOTDIR}var ${findargs} -name tcp.log -o -name \
.linux-sniff -o -name sniff-l0g -o -name core_ -o -wholename ${ROOTDIR}usr/lib/in.httpd -o \
-wholename ${ROOTDIR}usr/lib/in.pop3d"

        ### t0rn
        expertmode_output "${find} ${ROOTDIR}etc ${ROOTDIR}sbin \
${ROOTDIR}usr/src/.puta ${ROOTDIR}lib ${ROOTDIR}usr/info -name \
ttyhash -o -name xlogin -o -name ldlib.tk -o -name .t?rn"

        LIBS=
        [ -d "${ROOTDIR}lib" ] && LIBS="${ROOTDIR}lib"
        [ -d "${ROOTDIR}usr/lib" ] && LIBS="${LIBS} ${ROOTDIR}usr/lib"
        [ -d "${ROOTDIR}usr/local/lib" ] && \
           LIBS="${LIBS} ${ROOTDIR}usr/local/lib"

        expertmode_output "${find} ${LIBS} -name libproc.a"

        ## Lion Worm
        expertmode_output "${find} ${ROOTDIR}dev/.lib/lib -name 1i0n.sh
2> /dev/null"

        ### ark
        expertmode_output "${find} ${ROOTDIR}dev -name ptyxx"
        expertmode_output "${find} ${ROOTDIR}usr/doc -name '... '"
        expertmode_output "${find} ${ROOTDIR}usr/lib -name '.ark*'"

        ### RK17
        expertmode_output "${find} ${ROOTDIR}bin -name rtty -o -name squit"
        expertmode_output "${find} ${ROOTDIR}sbin -name pback"
        expertmode_output "${find} ${ROOTDIR}usr/man/man3 -name psid 2> /dev/null"
        expertmode_output "${find} ${ROOTDIR}proc -name kset 2> /dev/null"
        expertmode_output "${find} ${ROOTDIR}usr/src/linux/modules -name \
autod.o -o -name soundx.o 2> /dev/null"
        expertmode_output "${find} ${ROOTDIR}usr/bin -name gib -o \
-name ct -o -name snick -o -name kfl"

        CGIDIR=""
        for cgidir in www/httpd/cgi-bin www/cgi-bin var/www/cgi-bin \
var/lib/httpd/cgi-bin usr/local/httpd/cgi-bin usr/local/apache/cgi-bin \
home/httpd/cgi-bin usr/local/apache2 usr/local/www usr/lib;
        do
           [ -d "${ROOTDIR}${cgidir}" ] && CGIDIR="${CGIDIR} ${ROOTDIR}${cgidir}"
        done
        BACKDOORS="number.cgi void.cgi psid becys.cgi nobody.cgi bash.zk.cgi alya.cgi \
shell.cgi alin.cgi httpd.cgi linux.cgi sh.cgi take.cgi bogus.cgi alia.cgi all4one.cgi \
zxcvbnm.cgi secure.cgi ubb.cgi r57shell.php"
        for j in ${CGIDIR}; do
            for i in ${BACKDOORS}; do
                [ -f "${j}/${i}" ] && echo "${j}/${i}"
            done
        done

        ### rsha
        expertmode_output "${find} ${ROOTDIR}bin ${ROOTDIR}usr/bin -name kr4p \
-o -name n3tstat -o -name chsh2"
        expertmode_output "${find} ${ROOTDIR}etc/rc.d/rsha"
        expertmode_output "${find} ${ROOTDIR}etc/rc.d/arch/alpha/lib/.lib \
${ROOTDIR}usr/src/linux/arch/alpha/lib/.lib/"

        ### ShitC Worm
        expertmode_output "${find} ${ROOTDIR}bin ${ROOTDIR}sbin -name home \
-o -name frgy -o -name sy"
        expertmode_output "${find} ${ROOTDIR}usr/bin -type d -name dir"
        expertmode_output "${find} ${ROOTDIR}usr/sbin -type d -name in.slogind"

        ### Omega Worm
        expertmode_output "${find} ${ROOTDIR}dev -name chr"

        ### rh-sharpe
        expertmode_output "${find} ${ROOTDIR}bin ${ROOTDIR}usr/bin -name lps \
-o -name .ps -o -name lpstree -o -name .lpstree -o -name lkillall \
-o -name ldu -o -name lnetstat"
        expertmode_output "${find} ${ROOTDIR}usr/include/rpcsvc -name du"

        ### Adore Worm
        expertmode_output "${find} ${ROOTDIR}usr/lib ${ROOTDIR}usr/bin \
-name red.tar -o -name start.sh -o -name klogd.o -o -name 0anacron-bak \
-o -name adore"
        expertmode_output "${find} ${ROOTDIR}usr/lib/lib"
        expertmode_output "${find} ${ROOTDIR}usr/lib/libt"

        ### suspicious files and dirs
        suspects="/usr/lib/pt07 /usr/bin/atm /tmp/.cheese /dev/ptyzx /dev/ptyzg /usr/bin/sourcemask /dev/ida /dev/xdf* /usr/lib/libx?otps /sbin/init.zk"
        DIR=${ROOTDIR}usr/lib
        [ -d "${ROOTDIR}usr/man" ] && DIR="${DIR} ${ROOTDIR}usr/man"
        [ -d "${ROOTDIR}lib" ] && DIR="${DIR} ${ROOTDIR}lib"
        [ -d "${ROOTDIR}usr/lib" ] && DIR="${DIR} ${ROOTDIR}usr/lib"
        expertmode_output "${find} ${DIR} -name '.[A-Za-z]*'"
        expertmode_output "${find} ${DIR} -type d -name '.*'"
        expertmode_output "${find} ${DIR} -name '...*'"
        expertmode_output "${ls} ${suspects}"

        ### Maniac RK
        expertmode_output "${find} ${ROOTDIR}usr/bin -name mailrc"

        ### Ramen Worm
        expertmode_output "${find} ${ROOTDIR}usr/src/.poop \
${ROOTDIR}tmp/ramen.tgz ${ROOTDIR}etc/xinetd.d/asp"

        ### Sadmind/IIS Worm
        expertmode_output "${find} ${ROOTDIR}dev/cuc"

        ### Monkit
        expertmode_output "${find} ${ROOTDIR}lib/defs"

        ### Showtee
       expertmode_output "${ls} ${ROOTDIR}usr/lib/.egcs \
${ROOTDIR}usr/lib/.wormie \
${ROOTDIR}usr/lib/.kinetic ${ROOTDIR}usr/lib/liblog.o \
${ROOTDIR}usr/include/addr.h  ${ROOTDIR}usr/include/cron.h \
${ROOTDIR}usr/include/file.h ${ROOTDIR}usr/include/proc.h \
${ROOTDIR}usr/include/syslogs.h ${ROOTDIR}usr/include/chk.h"

       ### Optickit
       expertmode_output "${find} ${ROOTDIR}usr/bin -name xchk -o -name xsf"

       ### T.R.K
       expertmode_output "${find} ${ROOTDIR}usr/bin -name soucemask -o -name ct"
       ### MithRa's Rootkit
       expertmode_output "${find} ${ROOTDIR}usr/lib/locale -name uboot"


       ### OpenBSD rootkit v1
       if [ \( "${SYSTEM}" != "SunOS" -a "${SYSTEM}" != "Linux" \) -a ! -f "${ROOTDIR}usr/lib/security/libgcj.security" ]
          then
          expertmode_output "${find} ${ROOTDIR}usr/lib/security"
       fi

       ### LOC rootkit
       expertmode_output "${find} ${ROOTDIR}tmp -name xp -o -name kidd0.c"

       ### Romanian rootkit
       expertmode_output "${ls} ${ROOTDIR}usr/include/file.h \
${ROOTDIR}usr/include/proc.h ${ROOTDIR}usr/include/addr.h \
${ROOTDIR}usr/include/syslogs.h"

      ## HKRK rootkit
      ${egrep} "\.hk" "${ROOTDIR}etc/rc.d/init.d/network" 2>/dev/null

      ## Suckit rootkit
      expertmode_output "${strings} ${ROOTDIR}sbin/init | ${egrep} '\.sniffer'"
      expertmode_output "cat ${ROOTDIR}proc/1/maps | ${egrep} init."
      expertmode_output "cat ${ROOTDIR}dev/.golf"

      ## Volc rootkit
      expertmode_output "${ls} ${ROOTDIR}usr/bin/volc"
      expertmode_output "${find} ${ROOTDIR}usr/lib/volc"

      ## Gold2 rootkit
      expertmode_output "${ls} ${ROOTDIR}usr/bin/ishit"

      ## TC2 Worm
      expertmode_output "${ls} ${ROOTDIR}usr/bin/util ${ROOTDIR}usr/info \
${ROOTDIR}usr/sbin/initcheck ${ROOTDIR}usr/sbin/ldb"

      ## Anonoiyng rootkit
      expertmode_output "${ls} ${ROOTDIR}usr/sbin/mech* ${ROOTDIR}usr/sbin/kswapd"

      ## ZK rootkit
      expertmode_output "${ls} ${ROOTDIR}etc/sysconfig/console/load*"

      ## ShKit
      expertmode_output "${ls} ${ROOTDIR}lib/security/.config ${ROOTDIR}etc/ld.so.hash"

      ## AjaKit
      expertmode_output "${find} ${ROOTDIR}lib -name .ligh.gh"
      expertmode_output "${find} ${ROOTDIR}dev -name tux"

      ## zaRwT
      expertmode_output "${find} ${ROOTDIR}bin -name imin -o -name imout"

      ## Madalin rootkit
      expertmode_output "${find} ${ROOTDIR}usr/include -name icekey.h -o \
-name iceconf.h -o -name iceseed.h"

      ## Fu rootkit
      expertmode_output "${find} ${ROOTDIR}sbin ${ROOTDIR}bin \
      ${ROOTDIR}usr/include -name xc -o -name .lib -o name ivtype.h"

      ## Kenga3 Rookit
      expertmode_output "${find} ${ROOTDIR}usr/include/. ."

      ## ESRK Rookit
      expertmode_output "${ls} -l ${ROOTDIR}usr/lib/tcl5.3"

      ## rootedoor
      for i in $("${echo}" "${PATH}"|tr -s ':' ' '); do
         expertmode_output "${ls} -l ${ROOTDIR}${i}/rootedoor"
      done
      ## ENYE-LKM
      expertmode_output "${ls} -l ${ROOTDIR}etc/.enyeOCULTAR.ko"

      ## SSJD Operation Windigo  (Linux/Ebury)
      ssh=$(loc ssh ssh "$pth")
      if $ssh -V 2>&1 | ${egrep} "OpenSSH_[1-5]\.|OpenSSH_6\.[0-7]" >/dev/null; then
         expertmode_output "${ssh} -G 2>&1  | ${grep} -e illegal -e unknow"
      fi

      ## Mumblehard backdoor/botnet
      expertmode_output "cat ${ROOTDIR}var/spool/cron/crontabs | ${egrep} var/tmp"

      ## Backdoors.Linux.Mokes.a
      expertmode_output "${ls} -l ${ROOTDIR}tmp/ss0-[0-]9*"
      expertmode_output "${ls} -l ${ROOTDIR}tmp/kk0-[0-]9*"

      ## Malicious TinyDNS
      expertmode_output "${ls} -l '${ROOTDIR}home/ ./root/'"

      ## Linux/Xor.DDoS
      expertmode_output "${find} ${ROOTDIR}tmp -executable -type f"
      expertmode_output "${find} ${ROOTDIR}etc/cron.hourly"

      ## CrossRAT
      expertmode_output "${find} ${ROOTDIR}usr/var ${findargs} -name mediamgrs.jar"

      ## Hidden Cobra  (IBM AIX)
      expertmode_output "${find} ${ROOTDIR}tmp/.ICE-unix ${findargs} -name *.so"

      ## Rocke Monero Miner
      expertmode_output "${find} ${ROOTDIR}etc ${findargs} -name ld.so.pre -o -name xig"

      ## PWNLNX4 - An LKM Roottkit
      expertmode_output "${find} ${ROOTDIR}opt/uOnlineBuilder64 ${ROOTDIR}var/tmp/.1 ${ROOTDIR}var/tmp/Linux_Server"

      ## PWNLNX6 - An LKM Roottkit
      expertmode_output "${find} ${ROOTDIR}tmp/suterusu"

      ## Umbreon
      expertmode_output "${find} ${ROOTDIR}usr/share/libc.so*"

      ## KINSING.A Backdoor
      expertmode_output "${find} ${ROOTDIR}tmp/kdevtmp*"

      ## Syslogk LKM rootkit
      expertmode_output "${echo} 1> ${ROOTDIR}proc/syslogk"
      expertmode_output "${ls} ${ROOTDIR}proc/syslogk"

      ## Kovid LKM rootkit
      #${kill} -SIGCONT 31337
      expertmode_output "${ls} ${ROOTDIR}proc/kovid"
      #${kill} -SIGCONT 31337
      expertmode_output "${ls} ${ROOTDIR}proc/kovid"

      ## RotaJakiro
      expertmode_output "${ls} ${ROOTDIR}bin/system-daemon"
      #
      ## Tsunami DDoS Malware
      expertmode_output "${ls} ${ROOTDIR}bin/a ${ROOTDIR}bin/cls"

      ## Linux BPFDoor
      expertmode_output "${egrep} packet_recvmsg ${ROOTDIR}proc/*/stack"

      ## Common SSH-SCANNERS
      expertmode_output "${find} ${ROOTDIR}tmp ${ROOTDIR}var/tmp ${findargs} -name vuln.txt -o -name ssh-scan -o -name pscan2"

      ### shell history file check
      if [ ! -z "${SHELL}" -a ! -z "${HOME}" ]; then
      expertmode_output "${find} ${ROOTDIR}${HOME} -maxdepth 1 -name .*history \
 -size 0"
      expertmode_output "${find} ${ROOTDIR}${HOME} -maxdepth 1 -name .*history \
 \( -links 2 -o -type l \)"
      fi

      return 5
   ### expert mode ends here
   fi

   ###
   ### suspicious files and sniffer's logs
   ###
   suspects="usr/lib/pt07 usr/bin/atm tmp/.cheese dev/ptyzx dev/ptyzy \
usr/bin/sourcemask dev/ida dev/xdf1 dev/xdf2 usr/bin/xstat \
tmp/982235016-gtkrc-429249277 usr/bin/sourcemask /usr/bin/ras2xm \
usr/sbin/in.telnet sbin/vobiscum  usr/sbin/jcd usr/sbin/atd2 usr/bin/.etc .lp \
etc/ld.so.hash sbin/init.zk usr/lib/in.httpd usr/lib/in.pop3d nlsadmin"
   dir="var/run/.tmp lib/.so usr/lib/.fx var/local/.lpd dev/rd/cdb \
   var/spool/lp/admins/.lp var/adm/sa/.adm usr/lib/lib.so1.so"

	 # finish the 'Checking `aliens'...' line written by the main loop
	 [ "$QUIET" != "t" ] && echo "started"
	 _start "suspicious files in ${ROOTDIR}dev"
	 # in an lxc container, /dev/console has a device bind-mounted over it,
	 # so the next line tries to run egrep on /dev/console even with '-type f'
	 # so we need to add '--devices=skip' to grep
   files=$("${find}" "${ROOTDIR}dev" -type f -exec ${egrep} --devices=skip -l "^[0-5] " {} \; 2>/dev/null)
   _report "The following suspicious files were found in ${ROOTDIR}dev" "$files"
     _start "known suspicious directories"
     outmsg="no"
     for i in ${dir}; do
         if [ -d "${ROOTDIR}${i}" ]; then
             f=$(_filter "${ROOTDIR}${i}/" "")
             if [ -n "$f" ]; then
                 if [ "$outmsg" = "no" ]; then
                     _warn "Suspect directory $f found. Looking for sniffer logs:"
                     outmsg="yes"
                 else
                     # we already ended any 'Searching for...' line
                     echo "Suspect directory $f found. Looking for sniffer logs:"
                 fi
                 # print dir and contents
                 find_and_check "${ROOTDIR}${i}/"
                 echo
             fi
         fi
   done
   [ "$outmsg" = "no" ] && _not_found

   _start "known suspicious files"
   files=""
   for i in ${suspects}; do
	   if [ -f "${ROOTDIR}${i}" ]; then
		   files=$(_filter "${ROOTDIR}$i" "$files")
	   fi
   done
   _report "The following known suspicious files were found" "$files"

   _start "sniffer's logs"
   files=$(set -f; find_and_check "${ROOTDIR}dev" "${ROOTDIR}tmp" "${ROOTDIR}lib" "${ROOTDIR}etc" "${ROOTDIR}var" \
     ${findargs} \( -name "tcp.log" -o -name ".linux-sniff" -o -name "sniff-l0g" -o -name "core_" \))
   _report "The following potential sniffer's logs were found" "${files}"

lookfor_rootkit() {
   rkname=$1; files=$2; dirs=$3; # file/directory names cannot have whitespace
   _start "$rkname rootkit"

   bad="";
   for f in $files; do
       if [ -e "${ROOTDIR}${f}" ]; then
           bad=$(_filter "${ROOTDIR}$f" "$bad")
       fi
   done
   for d in $dirs ; do
       if [ -d "${ROOTDIR}${d}" ]; then
           bad=$(_filter "${ROOTDIR}${d}/" "$bad")
       fi
   done
   _report "Possible $rkname rootkit installed" "$bad"
}

   ### HiDrootkit
   lookfor_rootkit "HiDrootkit" "" "var/lib/games/.k"

   ### t0rn
   lookfor_rootkit "t0rn" "etc/ttyhash sbin/xlogin lib/ldlib.tk" \
       "usr/src/.puta usr/info/.t0rn"

   ### t0rn v8
   _start "t0rn v8 (or variation)"
   LIBS=""
   [ -d "${ROOTDIR}lib" ] && LIBS="${ROOTDIR}lib"
   [ -d "${ROOTDIR}usr/lib" ] && LIBS="${LIBS} ${ROOTDIR}usr/lib"
   [ -d "${ROOTDIR}usr/local/lib" ] && LIBS="${LIBS} ${ROOTDIR}usr/local/lib"
   if [  "$SYSTEM" != "FreeBSD" ]; then
       files=$(set -f; find_and_check ${LIBS} ${findargs} -name libproc.a)
       _report "Possible t0rn v8 (or variation) rootkit installed" "${files}"
   else
       _not_tested
   fi

   ### Lion Worm
   lookfor_rootkit "Lion" "bin/in.telnetd bin/mjy" "usr/info/.torn dev/.lib"

   ### RSHA rootkit
   lookfor_rootkit "RSHA" "bin/kr4p usr/bin/n3tstat usr/bin/chsh2 \
       usr/bin/slice2 usr/src/linux/arch/alpha/lib/.lib/.1proc \
       etc/rc.d/arch/alpha/lib/.lib/.1addr" "etc/rc.d/rsha \
       etc/rc.d/arch/alpha/lib/.lib"

   ### RH-Sharpe rootkit
   lookfor_rootkit "RH-Sharpe" "bin/lps usr/bin/lpstree	\
       usr/bin/ltop usr/bin/lkillall usr/bin/ldu		\
       usr/bin/lnetstat usr/bin/wp usr/bin/shad		\
       usr/bin/vadim usr/bin/slice usr/bin/cleaner		\
       usr/include/rpcsvc/du" ""

   ### ark rootkit - cant use lookfor_rookit as one dir has a space in it
   _start "Ambient (ark) rootkit"
   files=""
   for dir in "${ROOTDIR}dev/ptyxx" "${ROOTDIR}usr/doc/... "; do
       if [ -d "$dir" ]; then
           files=$(_filter "$dir/" "$files")
       fi
   done
   f="${ROOTDIR}usr/lib/.ark?"
   if [ -e "$f" ]; then
       files=$(_filter "$f" "$files")
   fi
   _report "Possible Ambient's rootkit (ark) installed" "$files"

   ### suspicious files and dirs
   _start "suspicious files and dirs"
   DIR="${ROOTDIR}usr/lib"
   [ -d "${ROOTDIR}usr/man" ] && DIR="$DIR ${ROOTDIR}usr/man"
   [ -d "${ROOTDIR}lib" ] && DIR="$DIR ${ROOTDIR}lib"

   # matches files and directories named '...' and '.. ' but not "." or ".."
   files=$("${find}" ${DIR} -name ".*" 2>/dev/null)
   outmsg=""
   for name in $files; do
       outmsg=$(_filter "$name" "$outmsg")
   done
   _report "The following suspicious files and directories were found" "$outmsg"

   ### LPD Worm
   _start "LPD Worm"

   if ${egrep} -q "^kork" "${ROOTDIR}etc/passwd" 2>/dev/null || \
      ${egrep} -q '^[[:space:]]*666[[:space:]]' "${ROOTDIR}etc/inetd.conf" 2>/dev/null; then
       _warn "Possible LPD worm installed (based on contents of ${ROOTDIR}etc/passwd or ${ROOTDIR}etc/inetd.conf)\n"
   elif [ -d "${ROOTDIR}dev/.kork" ] || [ -f "${ROOTDIR}bin/.ps" ] || [ -f "${ROOTDIR}usr/bin/.ps" ] || \
            [ -f "${ROOTDIR}bin/.login" ] || [ -f "${ROOTDIR}usr/bin/.login" ]; then
       _warn "Possible LPD worm installed (based on files found)\n"
   else
       _not_found
   fi

   ### Ramem Worm
     lookfor_rootkit "Ramen Worm" "tmp/ramen.tgz etc/xinetd.d/asp" "usr/src/.poop"

   ### Maniac rootkit
   _start "Maniac rootkit"
   files=$(set -f; find_and_check "${ROOTDIR}usr/bin" ${findargs} -name mailrc)
   _report "Possible Maniac rootkit installed" "${files}"

   ### RK17 rookit
   _start "RK17 rootkit"

   CGIDIR=""
   for cgidir in www/httpd/cgi-bin www/cgi-bin var/www/cgi-bin \
var/lib/httpd/cgi-bin usr/local/httpd/cgi-bin usr/local/apache/cgi-bin \
home/httpd/cgi-bin usr/local/apache2  usr/local/www usr/lib; do
       [ -d "${ROOTDIR}${cgidir}" ] && CGIDIR="$CGIDIR ${ROOTDIR}${cgidir}"
   done
   files=$(set -f; find_and_check "${ROOTDIR}bin" "${ROOTDIR}usr/bin" ${findargs} '(' -name rtty -o -name squit ')')
   i=$(set -f; find_and_check "${ROOTDIR}sbin" ${findargs} -name pback)
   if [ -z "$files" ]; then
       files="$i"
   else
       files="$files\n$i"
   fi
   i=$(set -f; find_and_check "${ROOTDIR}usr/man/man3" ${findargs} -name psid)
   if [ -z "$files" ]; then
       files="$i"
   else
       files="$files\n$i"
   fi
   i=$(set -f; find_and_check "${ROOTDIR}proc" ${findargs} -name kset)
   if [ -z "$files" ]; then
       files="$i"
   else
       files="$files\n$i"
   fi
   i=$(set -f; find_and_check "${ROOTDIR}usr/src/linux/modules" ${findargs} '(' -name autod.o -o -name sound ')')
   if [ -z "$files" ]; then
       files="$i"
   else
       files="$files\n$i"
   fi
   i=$(set -f; find_and_check "${ROOTDIR}usr/bin" ${findargs} '(' -name gib -o -name ct -o -name snick -o -name kfl ')')
   if [ -z "$files" ]; then
       files="$i"
   else
       files="$files\n$i"
   fi

   BACKDOORS="number.cgi void.cgi psid becys.cgi nobody.cgi bash.zk.cgi alya.cgi \
shell.cgi alin.cgi httpd.cgi linux.cgi sh.cgi take.cgi bogus.cgi alia.cgi all4one.cgi \
zxcvbnm.cgi secure.cgi ubb.cgi r57shell.php"
   for j in ${CGIDIR}; do
       for i in ${BACKDOORS}; do
           if [ -f "${j}/${i}" ]; then
               files=$(_filter "${j}/${i}" "$files")
           fi
       done
   done
   _report "Possible RK17 rootkit installed" "${files}"

   ### Ducoci rootkit
   _start "Ducoci rootkit"
   files=$(set -f; find_and_check ${CGIDIR} ${findargs} -name last.cgi)
   _report "Possible Ducoci rootkit installed" "${files}"

   ### Adore Worm
   _start "Adore Worm"

   files=$(set -f; find_and_check "${ROOTDIR}usr/lib" "${ROOTDIR}usr/bin" ${findargs} '(' -name red.tar -o \
       -name start.sh -o -name klogd.o -o -name 0anacron-bak -o -name adore ')')
   if [ -z "${files}" ]; then
       _not_found
   else
	   i=$(set -f; find_and_check "${ROOTDIR}usr/lib/lib" "${ROOTDIR}usr/lib/libt" ${findargs})
	   if [ -n "$i" ]; then
		   files="$files\n${i}"
	   fi
       _warn "Possible Adore Worm installed:\n${files}\n"
   fi

   ### ShitC Worm
   _start "ShitC Worm"
   files=$(set -f; find_and_check "${ROOTDIR}bin" "${ROOTDIR}usr/bin" ${findargs} '(' -name homo -o -name frgy -o -name dy ')')
   i=$(set -f; find_and_check "${ROOTDIR}usr/bin" ${findargs} -type d -name dir)
   if [ -z "$files" ]; then
       files="$i"
   elif [ -n "$i" ]; then
       files="$files\n$i"
   fi # else files non-empty, i empty
   i=$(set -f; find_and_check "${ROOTDIR}usr/sbin" ${findargs} -name in.slogind)
   if [ -z "$files" ]; then
       files="$i"
   elif [ -n "$i" ]; then
       files="$files\n$i"
   fi
   _report "Possible ShitC Worm installed" "${files}"

   ### Omega Worm
   _start "Omega Worm"
   files=$(set -f; find_and_check "${ROOTDIR}dev" ${findargs} -name chr)
   _report "Possible Omega Worm installed" "${files}"

   ### China Worm (Sadmind/IIS Worm)
   _start "Sadmind/IIS Worm"
   files=$(set -f; find_and_check "${ROOTDIR}dev/cuc" ${findargs})
   _report "Possible Sadmin/IIS Worm installed" "${files}"

   ### MonKit
   _start "MonKit"
   files=$(set -f; find_and_check "${ROOTDIR}lib/defs" "${ROOTDIR}usr/lib/libpikapp.a" ${findargs})
   _report "Possible MonKit installed" "${files}"

   ### Showtee
   lookfor_rootkit "Showtee" \
                   "usr/lib/liblog.o usr/include/addr.h usr/include/cron.h usr/include/file.h usr/include/proc.h usr/include/syslogs.h usr/include/chk.h" \
                   "usr/lib/.egcs usr/lib/.kinetic usr/lib/.wormie"

   ### OpticKit
   _start "OpticKit"
   files=$(set -f; find_and_check "${ROOTDIR}usr/bin/xchk" "${ROOTDIR}usr/bin/xsf" ${findargs})
   _report "Possible OpticKit installed" "${files}"

   ### T.R.K
   _start "T.R.K"
   files=$(set -f; find_and_check "${ROOTDIR}usr/bin" ${findargs} '(' -name xchk -o -name xsf ')')
   _report "Possible T.R.K installed" "${files}"

   ### Mithra's Rootkit
   _start "Mithra rootkit"
   files=$(set -f; find_and_check "${ROOTDIR}usr/lib/locale" ${findargs} -name uboot)
   _report "Possible Mithra installed" "${files}"

   ### OpenBSD rootkit v1
   _start "OBSD rootkit v1"
   if [ "${SYSTEM}" != "SunOS" ] && [ "${SYSTEM}" != "Linux" ]; then
       if [ ! -f "${ROOTDIR}usr/lib/security/libgcj.security" ]; then
           files=$(set -f; find_and_check "${ROOTDIR}usr/lib/security" ${findargs} )
           if [ "${files}" = "" ] || [ "${SYSTEM}" = "HP-UX" ]; then
               _not_found
           else
               _warn "Possible OpenBSD rootkit installed:\n${files}\n"
           fi
       else
           _not_found
       fi
   else
       _not_tested
   fi

   ### LOC rootkit
   _start "LOC rootkit"
   files=$(set -f; find_and_check "${ROOTDIR}tmp" ${findargs} '(' -name xp -o -name kidd0.c ')')
   if [ -z "${files}" ]; then
       _not_found
   else
       _warn "Possible LOC rootkit installed:\n${files}"
       i=$(loc epic "" "$pth")
       if [ -n "$i" ]; then
           _filter "$i" ""
       fi
   fi

   ### Romanian rootkit
   lookfor_rootkit  "Romanian" "usr/include/file.h usr/include/proc.h usr/include/addr.h usr/include/syslogs.h" ""

   ### HKRK
   _start "HKRK rootkit"
   file="${ROOTDIR}etc/rc.d/init.d/network"
   if [ -f "$file" ] && ${egrep} -q "\.hk" "$file" 2>/dev/null ; then
       file=$(_filter "$file" "")
       if [ -n "$file" ]; then
           _warn "Possible HKRK rootkit installed in ${file}\n"
       else
           _not_found
       fi
   else
       _not_found
   fi

   ### Suckit
   _start "Suckit rootkit"
   if [ -f "${ROOTDIR}sbin/init" ]; then
      if [ "${SYSTEM}" != "HP-UX" ] && ( "${strings}" "${ROOTDIR}sbin/init" | ${egrep} '\.sniffer'   || \
          ${egrep} "init." "${ROOTDIR}proc/1/maps" ) >/dev/null 2>&1
      then
          # ignore false positive  bug #740898
          # also ignore false positive on non-systemd init systems. See bug #901557
          if [ ! -h "${ROOTDIR}sbin/init" ] || \
                 readlink -f  "${ROOTDIR}sbin/init" | ${egrep} -q "/sbin/upstart$|/systemd$" 2>/dev/null; then
              _not_found
          else
              _warn "Possible Suckit: ${ROOTDIR}sbin/init INFECTED\n"
          fi
      else
          if [ -d "${ROOTDIR}dev/.golf" ]; then
              _warn "Possible Suckit:\n${ROOTDIR}dev/.golf/\n"
          else
              _not_found
          fi
      fi
   else
       _not_found
   fi

   ### Volc
   lookfor_rootkit "Volc" "usr/bin/volc usr/lib/volc" ""

   ### Gold2
   lookfor_rootkit "Gold2" "usr/bin/ishit" ""

   ### TC2 Worm
   lookfor_rootkit "TC2" "usr/sbin/initcheck usr/sbin/ldb" \
                   "usr/info/.tc2k usr/bin/util"

   ### ANONOYING Rootkit
   lookfor_rootkit "Anonoying" "usr/sbin/mech usr/sbin/kswapd"

   ### ZK Rootkit
   lookfor_rootkit "ZK" "etc/sysconfig/console/load.zk"

   ### ShKit
   lookfor_rootkit "ShKit" "lib/security/.config etc/ld.so.hash"

   ### AjaKit
   lookfor_rootkit "AjaKit" "" "lib/.ligh.gh dev/tux"

   ### zaRwT
   lookfor_rootkit "zaRwT" "bin/imin bin/imout"

   ### Madalin rootkit
   lookfor_rootkit "Madalin" "usr/include/icekey.h usr/include/iceconf.h usr/include/iceseed.h" ""

   ### Fu rootkit
   lookfor_rootkit "Fu" "sbin/xc bin/.lib usr/include/ivtype.h" ""

   ## Kenga3 Rookit - cant use lookfor_rootkit due to space
   _start "Kenga3 rootkit"
   files=$(set -f; find_and_check "${ROOTDIR}usr/include/. ./" ${findargs})
   _report "Possible Kenga3 rootkit installed" "$files"

   ### ESRK
   lookfor_rootkit ESRK "" "usr/lib/tcl5.3"

   ## rootedoor
   _start "rootedoor"
   files=""
   for i in $($echo "$pth" | tr -s ':' ' '); do
       if [ -f "${i}/rootedoor" ]; then
           files=$(_filter "${i}/rootedoor" "$files")
       fi
   done
   _report "Possible rootedoor installed" "$files"

   ### ENYELKM
   lookfor_rootkit "ENYELKM" "" "etc/.enyelkmOCULTAR.ko"

   ## Common SSH-SCANNERS
   _start "common ssh-scanners"
   ssh=$(loc ssh ssh "$pth")
   files=$(set -f; find_and_check "${ROOTDIR}tmp" "${ROOTDIR}var/tmp" ${findargs} \
                   '(' -name vuln.txt -o -name ssh-scan -o -name pscan2 ')')
   if [ -z "${files}" ]; then
       _not_found
   elif $ssh -G 2>&1 | "${grep}" usage > /dev/null; then
       _not_found
   else
       _warn "Possible ssh-scanner installed:\n${files}\n"
   fi

   ## SSJD Operation Windigo  (Linux/Ebury)
   LIBKEY="lib/x86_64-linux-gnu/libkeyutils.so.1"
   _start "Linux/Ebury 1.4 - Operation Windigo"
   if ${ssh} -V 2>&1 | ${egrep} "OpenSSH_[1-5]\.|OpenSSH_6\.[-0-7]" >/dev/null; then
       if ${ssh} -G 2>&1 | "${grep}" -e illegal -e unknow > /dev/null; then
           _not_found
       else
           _warn "${ssh} may be INFECTED by Linux/Ebury 1.4\n"
       fi
   else
       _not_tested
   fi

   _start "Linux/Ebury 1.6"
   file="${ROOTDIR}${LIBKEY}"
   if [ ! -f "$file" ]; then
       _not_tested
   else
       if "${strings}" -a "$file" | ${egrep} "(libns2|libns5|libpw3|libpw5|libsbr|libslr)" >/dev/null; then
           file=$(_filter "$file" "")
           if [ -n "$file" ]; then
               _warn "Possible Linux/Ebury 1.6 - Operation Windigo installed in ${file}"
           else
               _not_found
           fi
       else
           _not_found
       fi
   fi

   ## Linux Rootkit 64 bits
   _start "64-bit Linux Rootkit"
   file="${ROOTDIR}etc/rc.local"
   files=$(set -f; find_and_check "${ROOTDIR}usr/local/hide/" ${findargs})
   if ${egrep} -q module_init "$file" 2>/dev/null; then
	   files=$(_filter "$file" "$files")
   fi
   _report "Possible 64-bit Linux Rootkit" "$files"

   _start "64-bit Linux Rootkit modules"
   files=$(set -f; find_and_check "${ROOTDIR}lib/modules" ${findargs} -name module_init.ko)
   _report "Possible 64-bit rootkit modules installed" "${files}"

   ## Mumblehard backdoor/botnet
   _start "Mumblehard"
   files=""
   if [ -d "${ROOTDIR}var/spool/cron/crontabs" ]; then
       for f in "${ROOTDIR}var/spool/cron/crontabs"/*; do
           if [ -e "$f" ] && ${egrep} -q "var/tmp" "$f" 2>/dev/null; then
               files=$(_filter "$f" "$files")
           fi
       done
   fi
   _report "Possible Mumblehard backdoor installed" "$files"

   ## Backdoor.Linux.Mokes.a
   _start "Backdoor.Linux.Mokes.a"
   files=$(set -f; find_and_check "${ROOTDIR}tmp/" ${findargs} '(' -name "ss0-[0-9]*" -o -name "kk-[0-9]*" ')')
   _report "Possible Backdoor.Linux.Mokes.a installed" "${files}"

   ## Malicious TinyDNS
   _start "Malicious TinyDNS"
   files=$(set -f; find_and_check "${ROOTDIR}home/ ./" ${findargs})
   _report "Possible Malicious TinyDNS installed" "$files"

   ## Linux/Xor.DDoS
   _start "Linux.Xor.DDoS"
   files=$(set -f; find_and_check "${ROOTDIR}tmp/" ${findargs} -executable -type f)
   for i in "${ROOTDIR}etc/cron.hourly/udev.sh" "${ROOTDIR}etc/cron.hourly/gcc.sh"; do
       if [ -e "$i" ]; then
           files=$(_filter "$i" "$files")
       fi
   done
   _report "Possible Linux.Xor.DDoS installed" "${files}"

   ## Linux.Proxy 1.0
   _start "Linux.Proxy.1.0"
   if ${egrep} -i mother "${ROOTDIR}etc/passwd" >/dev/null 2>&1 ; then
       _warn "INFECTED: Possible Malicious Linux.Proxy.10 installed in /etc/passwd\n"
   else
       _not_found
   fi

   # Linux/CrossRAT
   _start "CrossRAT"
   files=$(set -f; find_and_check "${ROOTDIR}usr/var" -maxdepth 1 ${findargs} -name "mediamgrs.jar")
   _report "Possible Malicious CrossRAT installed" "$files"

   ## Hidden Cobra (IBM AIX)
   _start "Hidden Cobra"
   files=$(set -f; find_and_check "${ROOTDIR}tmp/.ICE-unix" -maxdepth 1 ${findargs} "(" -name "m*.so" -o -name  \
                 "engine.so" ")")
   _report "Possible Malicious Hidden Cobra installed" "$files"

   ### Rocke Monero Miner
   lookfor_rootkit "Rocke Miner" "ld.so.pre etc/xig" ""

   ## PWNLNX4 - An LKM Rootkit
   lookfor_rootkit "PWNLNX4 lkm" "" "uOnlineBuilder64 var/tmp/.1 var/tmp/Linux_Server"

   ## PWNLNX6 - Another LKM Rootkit
   lookfor_rootkit "PWNLNX6 lkm" "" "tmp/suterusu"

   ## Umbreon Linux Rootkit
   _start "Umbreon lrk"
   files=$(set -f; find_and_check "${ROOTDIR}usr/share" -maxdepth 1 ${findargs} -name 'libc.so.*' )
   _report "Possible Malicious UMBREON LRK installed" "$files"

   ## KINSING.A Backdoor
   lookfor_rootkit "Kinsing.a backdoor" "tmp/kdevtmpfsi" ""

   ## RotaJakiro Backdoor
   lookfor_rootkit "RotaJakiro backdoor" "bin/systemd-daemon" ""

   ## Syslogk LKM rootkit
   _start "Syslogk LKM rootkit"
   if [ "$mode" = "pm" ]; then
       _not_tested
   else
       ("${echo}" 1> "${ROOTDIR}proc/syslogk") >/dev/null 2>&1
       if "${ls}" "${ROOTDIR}proc/syslogk" >/dev/null 2>&1; then
           _warn "Possible Malicious Syslogk LKM rootkit installed: /proc/syslogk\n"
       else
           _not_found
       fi
   fi

   ## Kovid LKM rootkit
   f=""
   _start "Kovid LKM rootkit"
   for i in 1 2; do
       #${kill} -SIGCONT 31337 2>/dev/null # commented out as potentially dangerous
       if  "${ls}" "${ROOTDIR}proc/kovid" > /dev/null 2>&1 ; then
           if [ -z "$f" ]; then
               _warn "INFECTED: Possible Malicious Kovid LKM rootkit installed: ${ROOTDIR}proc/kovid\n"
               f="Kovid"
           fi
       fi
   done
   if [ "${f}" = "" ]; then
       _not_tested
       # warn "Kovid test is semi-disabled: to properly test run '$kill -SIGCONT 31337' and re-run"
   fi

   lookfor_rootkit "Tsunami DDoS Malware" "bin/a bin/cls bin/clean" ""

   _start "Linux BPF Door"
   files=$(${egrep} -l packet_recvmsg "${ROOTDIR}"proc/*/stack 2>/dev/null)
   _report "Possible Linux BPFDoor Malware installed" "$files"

   ### Suspect PHP files
   _start "suspect PHP files"
   files=$(set -f; "${find}" "${ROOTDIR}tmp" "${ROOTDIR}var/tmp" ${findargs} -name '*.php' 2>/dev/null)
   fileshead=$(set -f; "${find}" "${ROOTDIR}tmp" "${ROOTDIR}var/tmp" ${findargs} -type f -print0 2>/dev/null | PATH="$path_for_tools" "${xargs}" -0 -I@ ./check_php @)
   if [ -z "$files" ]; then
       files="$fileshead"
   else
       if [ -n "$fileshead" ]; then
           files="$files\n$fileshead"
       fi
   fi
   _report "The following suspicious PHP files were found" "${files}"

   ### shell history anomalies
   _start "zero-size shell history files in $HOME"
   if [ -d "$HOME" ]; then
       files=$(set -f; find_and_check "$HOME" -maxdepth 1 ${findargs} -name '.*history' -size 0)
       _report "Zero-size history files" "$files"
   else
       _warn "No \$HOME: $HOME"
   fi
   _start "hardlinked shell history files in $HOME"
   if [ -d "$HOME" ]; then
       files=$(set -f; find_and_check "$HOME" -maxdepth 1 ${findargs} -name '.*history' \( -links 2 -o -type l \))
       _report "shell history files hardlinked to another file" "$files"
   else
       _warn "No \$HOME: $HOME"
   fi
   [ "$QUIET" != "t" ] && printn "Checking \`aliens'..."
   [ "$QUIET" != "t" ] && echo "finished"
}

######################################################################
# util functions

# our which(1)
loc () {
    ### usage: loc filename filename_to_return_if_nothing_was_found "path"
    thing=$1
    dflt=$2
    for dir in $3; do
        if test -f "$dir/$thing"; then
            echo "$dir/$thing"
            exit 0
        fi
    done
    echo "${dflt}"
    exit 1
}

# find $1 either from ps(1) or using loc. (it only makes sense to use
# ps(1) if we are not using '-r')
getCMD() {
    if [ "$mode" = "rt" ]; then
        # prefer to test the running $1 if it appears in ps - this fails for sshd which as 'sshd: ..'
        # and not as '/usr/sbin/sshd'
        RUNNING=$("${ps}" "${ps_cmd}" | ${egrep} "${L_REGEXP}${1}${R_REGEXP}" | \
            ${egrep} -v grep | ${egrep} -v chkrootkit | _head -1 | "${awk}" '{ print $5 }')
        if [ -n "${RUNNING}" ] && [ -r "$RUNNING" ]; then
            CMD=${RUNNING}
            return 0
        fi
    fi
    # either using -r or $1 is not running: find in $pth
    CMD="$(loc "${1}" "${1}" "$pth")"
    return $?
}

expertmode_output() {
    echo "###"
    echo "### Output of: $1"
    echo "###"
    eval "$1" 2>&1
#    cat <<EOF
#`$1 2>&1`
#EOF
    return 0
}

exclude_fstype ()
{
  # Make sure a valid fstype has been provided.
  if ! echo "$1" | ${egrep} '^[A-Za-z0-9.]+$' > /dev/null 2>&1; then
    echo >&2 "Invalid fstype: $1"
    exit 1
  fi

   ## Check if -fstype $type works
   if "${find}" /etc -maxdepth 0 -fstype "$1" -prune >/dev/null 2>&1; then
       findargs="${findargs} -fstype $1 -prune -o "
   fi
}

######################################################################
# trojan functions

chk_chfn () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc chfn chfn "$pth")
    [ ${?} -ne 0 ] &&  return "${NOT_FOUND}"

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    case "${SYSTEM}" in
       Linux)
          if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" \
             >/dev/null 2>&1
          then
             STATUS=${INFECTED}
          fi;;
       FreeBSD)
           if [ "$("${echo}" "$V" | "${awk}" '{ if ( $1 >= 5.0) print 1; else print 0 }')" -eq 1 ];
           then
               n=1
           else
               n=2
           fi
           if [ "$("${strings}" -a "${CMD}" | ${egrep} -c "${GENERIC_ROOTKIT_LABEL}")" -ne "$n" ]; then
               STATUS=${INFECTED}
           fi;;
    esac
    return "${STATUS}"
}

chk_chsh () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc chsh chsh "$pth")
    [ ${?} -ne 0 ] && return "${NOT_FOUND}"

    REDHAT_PAM_LABEL="*NOT*"
    GENERIC_ROOTKIT_FEDORA=${GENERIC_ROOTKIT_LABEL}
    if [ -f  "${ROOTDIR}etc/system-release" ]; then
        v="0"$(${egrep} -i fedora "${ROOTDIR}etc/system-release" | "${cut}" -d " " -f 3)
        if [ "$v" -gt "32" ]; then
            GENERIC_ROOTKIT_FEDORA="bash|elite$|vejeta|\.ark|iroffer"
        fi
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    case "${SYSTEM}" in
       Linux)
          if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_FEDORA}" \
          >/dev/null 2>&1
          then
             if "${strings}" -a "${CMD}" | ${egrep} "${REDHAT_PAM_LABEL}" \
             >/dev/null 2>&1
             then
                :
             else
                STATUS=${INFECTED}
             fi
          fi;;
       FreeBSD)
           if [ "$("${echo}" "$V" | "${awk}" '{ if ($1 >= 5.0) print 1; else print 0}')" -eq 1 ]; then
               n=1
           else
               n=2
           fi
           if [ "$("${strings}" -a "${CMD}" | ${egrep} -c "${GENERIC_ROOTKIT_LABEL}")" -ne "$n" ]; then
               STATUS=${INFECTED}
           fi;;
    esac
    return "${STATUS}"
}

chk_login () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc login login "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if [ "$SYSTEM" = "SunOS" ]; then
        TROJED_L_L="porcao|/bin/xstat"
        if "${strings}" -a "${CMD}" | ${egrep} "${TROJED_L_L}" >/dev/null 2>&1; then
            return "${INFECTED}"
        else
            return "${NOT_TESTED}"
        fi
    fi
    GENERAL="^root$"
    TROJED_L_L="vejeta|^xlogin|^@\(#\)klogin\.c|lets_log|sukasuka|/usr/lib/.ark?|SucKIT|cocola"
    ret=$("${strings}" -a "${CMD}" | ${egrep} -c "${GENERAL}")
    if [ "${ret}" -gt 0 ]; then
        case "${ret}" in
        1) if [ "${SYSTEM}" = "OpenBSD" -a "$(echo "$V" | "${awk}" '{ if ($1 < 2.7 ||
$1 >= 3.0) print 1; else print 0}')" -eq 1 ]; then
               STATUS=${NOT_INFECTED}
           else
               STATUS=${INFECTED}
           fi;;
        2) if [ "${SYSTEM}" = "FreeBSD"  -o "${SYSTEM}" = "NetBSD" -o "${SYSTEM}" = "OpenBSD" -a "$(echo "${V}" | "${awk}" '{ if ($1 >= 2.8) print 1; else print 0 }')" -eq 1 ]; then
               STATUS=${NOT_INFECTED}
           else
               STATUS=${INFECTED}
           fi;;
        6|7) if [ "${SYSTEM}" = "HP-UX" ]; then
                 STATUS=${NOT_INFECTED}
             else
                 STATUS=${INFECTED}
             fi;;
        *) STATUS=${INFECTED};;
        esac
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${TROJED_L_L}" >/dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_passwd () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc passwd passwd "$pth")

    if [ ! -x "${CMD}" -a -x "${ROOTDIR}usr/bin/passwd" ]; then
       CMD="${ROOTDIR}usr/bin/passwd"
    fi
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if [ "${SYSTEM}" = "OpenBSD" -o "${SYSTEM}" = "SunOS" -o "${SYSTEM}" = "HP-UX" ]
    then
       return "${NOT_TESTED}"
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}|/lib/security" \
    >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_inetd () {
    STATUS=${NOT_INFECTED}
    getCMD 'inetd'
    if [ ! -r "${CMD}" -o "${CMD}" = '/' ]; then
        return "${NOT_TESTED}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" \
    >/dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_syslogd () {
    STATUS=${NOT_INFECTED}
SYSLOG_I_L="/usr/lib/pt07|/dev/pty[pqrs]|/dev/hd[als][0-7]|/dev/ddtz1|/dev/ptyxx|/dev/tux|syslogs\.h"
    CMD=$(loc syslogd syslogd "$pth")

    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${SYSLOG_I_L}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_hdparm () {
    STATUS=${NOT_INFECTED}
    HDPARM_INFECTED_LABEL="/dev/ida"
    CMD=$(loc hdparm hdparm "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${HDPARM_INFECTED_LABEL}" \
       >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_gpm () {
    STATUS=${NOT_INFECTED}
    GPM_INFECTED_LABEL="mingetty"
    CMD=$(loc gpm gpm "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GPM_INFECTED_LABEL}" \
       >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_mingetty () {
    STATUS=${NOT_INFECTED}
    MINGETTY_INFECTED_LABEL="Dimensioni|pacchetto"
    CMD=$(loc mingetty mingetty "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${MINGETTY_INFECTED_LABEL}" \
       >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_sendmail () {
    STATUS=${NOT_INFECTED}
    SENDMAIL_INFECTED_LABEL="fuck"
    CMD=$(loc sendmail sendmail "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${SENDMAIL_INFECTED_LABEL}" \
       >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_ls () {
    STATUS=${NOT_INFECTED}
LS_INFECTED_LABEL="/dev/ttyof|/dev/pty[pqrs]|/dev/hdl0|\.tmp/lsfile|/dev/hdcc|/dev/ptyxx|duarawkz|^/prof|/dev/tux|/security|file\.h"
    CMD=$(loc ls ls "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${LS_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_du () {
    STATUS=${NOT_INFECTED}
    DU_INFECTED_LABEL="/dev/ttyof|/dev/pty[pqrsx]|w0rm|^/prof|/dev/tux|file\.h"
    CMD=$(loc du du "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${DU_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_named () {
    STATUS=${NOT_INFECTED}
    NAMED_I_L="blah|bye"
    CMD=$(loc named named "$pth")

    if [ ! -r "${CMD}" ]; then
       CMD=$(loc in.named in.named "$pth")
       if [ ! -r "${CMD}" ]; then
           return "${NOT_FOUND}"
       fi
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${NAMED_I_L}" \
    >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_netstat () {
    STATUS=${NOT_INFECTED}
NETSTAT_I_L="/dev/hdl0/dev/xdta|/dev/ttyoa|/dev/pty[pqrsx]|/dev/cui|/dev/hdn0|/dev/cui221|/dev/dszy|/dev/ddth3|/dev/caca|^/prof|/dev/tux|grep|addr\.h|__bzero"
    CMD=$(loc netstat netstat "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${NETSTAT_I_L}" \
    >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_ps () {
   STATUS=${NOT_INFECTED}
PS_I_L="/dev/xmx|\.1proc|/dev/ttyop|/dev/pty[pqrsx]|/dev/cui|/dev/hda[0-7]|\
/dev/hdp|/dev/cui220|/dev/dsx|w0rm|/dev/hdaa|duarawkz|/dev/tux|/security|^proc\.h|ARRRGH\.so"
   CMD=$(loc ps ps "$pth")
   if [ "${?}" -ne 0 ]; then
       return "${NOT_FOUND}"
   fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${PS_I_L}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_pstree () {
    STATUS=${NOT_INFECTED}
    PSTREE_INFECTED_LABEL="/dev/ttyof|/dev/hda01|/dev/cui220|/dev/ptyxx|^/prof|/dev/tux|proc\.h"

    CMD=$(loc pstree pstree "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${PSTREE_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_crontab () {
    STATUS=${NOT_INFECTED}
    CRONTAB_I_L="crontab.*666"

    CMD=$(loc crontab crontab "$pth")

    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${CMD} -l -u nobody"
        return 5
    fi
    # slackware's crontab have a bug
    if  ( "${CMD}" -l -u nobody | $egrep [0-9] ) >/dev/null 2>&1 ; then
        if [ "${QUIET}" != "t" ]; then echo "WARNING"; fi
        echo "WARNING: crontab for nobody found, possible Lupper.Worm."
        if "${CMD}" -l -u nobody 2>/dev/null | ${egrep} "$CRONTAB_I_L" >/dev/null 2>&1
        then
            if [ "${QUIET}" = "t" ]; then
                echo "Checking for Lupper.Worm... INFECTED"
                # main loop will then print "checking crontab..INFECTED"
            else
                # main loop already printed "checking crontab... WARNING"
                printn "Checking for Lupper.Worm... "
                # main loop will 'close' the 'printn' with 'INFECTED'
            fi
            STATUS=${INFECTED}
        else
            if [ "${QUIET}" != "t" ]; then
                printn "Checking for Lupper.Worm... "
                echo "not infected"
            fi
        fi
    fi
    return "${STATUS}"
}

chk_top () {
    STATUS=${NOT_INFECTED}
    TOP_INFECTED_LABEL="/dev/xmx|/dev/ttyop|/dev/pty[pqrsx]|/dev/hdp|/dev/dsx|^/prof/|/dev/tux|^/proc\.h|proc_hackinit"

    CMD=$(loc top top "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${TOP_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_pidof () {
    STATUS=${NOT_INFECTED}
    TOP_INFECTED_LABEL="/dev/pty[pqrs]"
    CMD=$(loc pidof pidof "$pth")

    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${TOP_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_killall () {
    STATUS=${NOT_INFECTED}
    TOP_INFECTED_LABEL="/dev/ttyop|/dev/pty[pqrs]|/dev/hda[0-7]|/dev/hdp|/dev/ptyxx|/dev/tux|proc\.h"
    CMD=$(loc killall killall "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${TOP_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

# this seems to be missing a grep after strings? currently just
# testing if the files exist
chk_ldsopreload() {
   STATUS=${NOT_INFECTED}

   if [ "${SYSTEM}" = "Linux" ]
   then
      if [ ! -x ./strings-static ]; then
        _warn "ldsopreload not tested: can't exec ./strings-static"
        return "${NOT_TESTED}"
      fi

      if [ "${EXPERT}" = "t" ]; then
          expertmode_output "./strings-static -a ${CMD}"
          return 5
      fi

      ### strings must be a statically linked binary.
      if ./strings-static -a "${ROOTDIR}lib/libshow.so" "${ROOTDIR}lib/libproc.a" > /dev/null 2>&1
      then
         STATUS=${INFECTED}
      fi
   else
     STATUS=${NOT_TESTED}
   fi
   return "${STATUS}"
}

chk_basename () {
   STATUS=${NOT_INFECTED}
   CMD=$(loc basename basename "$pth")
   if [ "${?}" -ne 0 ]; then
       return "${NOT_FOUND}"
   fi

   if [ "${EXPERT}" = "t" ]; then
       expertmode_output "${strings} -a ${CMD}"
       expertmode_output "${ls} -l ${CMD}"
       return 5
   fi
   if "${strings}" -a "${CMD}" | ${egrep} -q "${GENERIC_ROOTKIT_LABEL}"
   then
       STATUS=${INFECTED}
   fi
   [ "$SYSTEM" != "OSF1" ] &&
   {
      if "${ls}" -l "${CMD}" | ${egrep} -q "^...s"
      then
         STATUS=${INFECTED}
      fi
   }
   return "${STATUS}"
}

chk_dirname () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc dirname dirname "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_traceroute () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc traceroute traceroute "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_rpcinfo () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc rpcinfo rpcinfo "$pth")
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_date () {
    STATUS=${NOT_INFECTED}
    S_L="/bin/.*sh"
    CMD=$(loc date date "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    [ "${SYSTEM}" = "FreeBSD" -a "$(echo "$V" | "${awk}" '{ if ($1 > 4.9) print 1; else print 0 }')" -eq 1 ] &&
    {
       N=$("${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" | \
          ${egrep} -c "$S_L")
       if [ "${N}" -ne 2 -a "${N}" -ne 0 ]; then
          STATUS=${INFECTED}
       fi
    } ||
    {
       if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
          then
          STATUS=${INFECTED}
       fi
    }
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_echo () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc echo echo "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_env () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc env env "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi

    return "${STATUS}"
}

chk_timed () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc timed timed "$pth")
    if [ ${?} -ne 0 ]; then
       CMD=$(loc in.timed in.timed "$pth")
       if [ ${?} -ne 0 ]; then
           return "${NOT_FOUND}"
       fi
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_identd () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc in.identd in.identd "$pth")
    if [ ${?} -ne 0 ]; then
       return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_init () {
    STATUS=${NOT_INFECTED}
    INIT_INFECTED_LABEL="UPX"
    CMD=$(loc init init "$pth")
    if [ ${?} -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${INIT_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_pop2 () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc in.pop2d in.pop2d "$pth")
    if [ ${?} -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_pop3 () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc in.pop3d in.pop3d "$pth")
    if [ ${?} -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_write () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc write write "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    WRITE_ROOTKIT_LABEL="bash|elite$|vejeta|\.ark"
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    if [ ! -f "${CMD}" ]; then
       STATUS=${NOT_FOUND}
       return "${STATUS}"
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${WRITE_ROOTKIT_LABEL}" | "${grep}" -v locale > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_w () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc w w "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    W_INFECTED_LABEL="uname -a"

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${W_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_vdir () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc vdir vdir "$pth")
    VDIR_INFECTED_LABEL="/lib/volc"
    if [ ! -r "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${VDIR_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_tar () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc tar tar "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

rexedcs () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc in.rexedcs in.rexedcs "$pth")
    if [ "${?}" -ne 0 ]
    then
        if [ "${QUIET}" != "t" ]; then echo "not found"; fi
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    STATUS=${INFECTED}
    echo "INFECTED: $CMD"
    return "${STATUS}"
}

chk_mail () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc mail mail "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    [ "${SYSTEM}" = "HP-UX" ] && return "${NOT_TESTED}"

    MAIL_INFECTED_LABEL="sh -i"

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${MAIL_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_biff () {
    STATUS=${NOT_INFECTED}
    CMD=$(loc biff biff "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GENERIC_ROOTKIT_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_egrep () {
    STATUS=${NOT_INFECTED}
    EGREP_INFECTED_LABEL="blah"
    CMD=$(loc egrep egrep "$pth")
    if [ "${?}" -ne 0 ]; then
       return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi
    [ -z "${CMD}" ] && return "${STATUS}"
    if "${strings}" -a "${CMD}" | ${egrep} "${EGREP_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_grep () {
    STATUS=${NOT_INFECTED}
    GREP_INFECTED_LABEL="givemer"
    CMD=$(loc grep grep "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        expertmode_output "${ls} -l ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${GREP_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    if "${ls}" -l "${CMD}" | ${egrep} "^...s" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_find () {
    STATUS=${NOT_INFECTED}
    FIND_INFECTED_LABEL="/dev/ttyof|/dev/pty[pqrs]|^/prof|/home/virus|/security|file\.h"
    CMD=$(loc find find "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${FIND_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_rlogind () {
    STATUS=${NOT_INFECTED}
    RLOGIN_INFECTED_LABEL="p1r0c4|r00t"
    CMD=$(loc in.rlogind in.rlogind "$pth")
    if [ ! -x "${CMD}" ]; then
        CMD=$(loc rlogind rlogind "$pth")
        if [ ! -x "${CMD}" ]; then
            return "${NOT_FOUND}"
        fi
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${RLOGIN_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_lsof () {
    STATUS=${NOT_INFECTED}
    LSOF_INFECTED_LABEL="^/prof"
    CMD=$(loc lsof lsof "$pth")
    if [ ! -x "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${LSOF_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_amd () {
    STATUS=${NOT_INFECTED}
    AMD_INFECTED_LABEL="blah"
    CMD=$(loc amd amd "$pth")
    if [ ! -x "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${AMD_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_slogin () {
    STATUS=${NOT_INFECTED}
    SLOGIN_INFECTED_LABEL="homo"
    CMD=$(loc slogin slogin "$pth")
    if [ ! -x "${CMD}" ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${SLOGIN_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_cron () {
    STATUS=${NOT_INFECTED}
    CRON_INFECTED_LABEL="/dev/hda|/dev/hda[0-7]|/dev/hdc0"
    CMD=$(loc cron cron "$pth")
    if [ "${?}" -ne 0 ]; then
        CMD=$(loc crond crond "$pth")
    fi
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${CRON_INFECTED_LABEL}" >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_ifconfig () {
    STATUS=${INFECTED}
    CMD=$(loc ifconfig ifconfig "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    IFCONFIG_NOT_INFECTED_LABEL="PROMISC"
    IFCONFIG_INFECTED_LABEL="/dev/tux|/session.null"
    if "${strings}" -a "${CMD}" | ${egrep} "${IFCONFIG_NOT_INFECTED_LABEL}" \
    >/dev/null 2>&1
    then
       STATUS=${NOT_INFECTED}
    fi
    if "${strings}" -a "${CMD}" | ${egrep} "${IFCONFIG_INFECTED_LABEL}" \
    >/dev/null 2>&1
    then
       STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_rshd () {
    STATUS=${NOT_INFECTED}
    case "${SYSTEM}" in
       Linux) CMD="${ROOTDIR}usr/sbin/in.rshd";;
       FreeBSD) CMD="${ROOTDIR}usr/libexec/rshd";;
       *) CMD=$(loc rshd rshd "$pth");;
    esac

    if [ ! -x "${CMD}" ] ;then
       return "${NOT_FOUND}"
    fi
    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    RSHD_INFECTED_LABEL="HISTFILE"
    if "${strings}" -a "${CMD}" | ${egrep} "${RSHD_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
        if ${egrep} "^#.*rshd" "${ROOTDIR}etc/inetd.conf" >/dev/null 2>&1 -o \
            "${ls}" "${ROOTDIR}etc/xinetd.d/rshd" >/dev/null 2>&1 ; then
           STATUS=${INFECTED_BUT_DISABLED}
        fi
    fi
    return "${STATUS}"
}

chk_tcpdump () {
    # this function is missing test for expertmode and is inconsistent with the other chk_* functions in terms of return values
   STATUS=${NOT_INFECTED}
   TCPDUMP_I_L="212.146.0.34:1963";
   _chk_netstat_or_ss;
   OPT="-an"
   if ${netstat} "${OPT}" 2>/dev/null | ${egrep} -q "${TCPDUMP_I_L}"; then
      STATUS=${INFECTED}
   fi
   return "${STATUS}"
}

chk_tcpd () {
    STATUS=${NOT_INFECTED}
    TCPD_INFECTED_LABEL="p1r0c4|hack|/dev/xmx|/dev/hdn0|/dev/xdta|/dev/tux"
    CMD=""
    [ -r "${ROOTDIR}etc/inetd.conf" ] &&
    CMD=$(${egrep} '^[^#].*tcpd' "${ROOTDIR}etc/inetd.conf" | _head -1 | \
         "${awk}" '{ print $6 }')
    if "${ps}" auwx | ${egrep} xinetd | ${egrep} -v grep >/dev/null 2>&1;  then
       CMD=$(loc tcpd tcpd "$pth")
    fi
    [ -z "${CMD}" ] && CMD=$(loc tcpd tcpd "$pth")

    [ "tcpd" = "${CMD}" -o ! -f "${CMD}" ] && return "${NOT_FOUND}";

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${TCPD_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_sshd () {
    STATUS=${NOT_INFECTED}
    SSHD2_INFECTED_LABEL="check_global_passwd|panasonic|satori|vejeta|\.ark|/hash\.zk"
    getCMD 'sshd'

    if [ ! -s "${CMD}" ]; then
       return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${SSHD2_INFECTED_LABEL}" \
       > /dev/null 2>&1
    then
        STATUS=${INFECTED}
        if "${ps}" "${ps_cmd}" | ${egrep} sshd >/dev/null 2>&1; then
           STATUS=${INFECTED_BUT_DISABLED}
        fi
    fi
    return "${STATUS}"
}

chk_su () {
    STATUS=${NOT_INFECTED}
    SU_INFECTED_LABEL="satori|vejeta|conf\.inv"
    CMD=$(loc su su "$pth")
    if [ "${?}" -ne 0 ]; then
        return "${NOT_FOUND}"
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${SU_INFECTED_LABEL}" > /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

chk_fingerd () {
    STATUS=${NOT_INFECTED}
    FINGER_INFECTED_LABEL="cterm100|${GENERIC_ROOTKIT_LABEL}"
    CMD=$(loc fingerd fingerd "$pth")

    if [ ${?} -ne 0 ]; then
        CMD=$(loc in.fingerd in.fingerd "$pth")
        if [ ${?} -ne 0 ]; then
           return "${NOT_FOUND}"
        fi
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${FINGER_INFECTED_LABEL}" \
> /dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}


chk_inetdconf () {
    # this function is inconsistent with the other chk_* functions in terms of return values
    STATUS=${NOT_INFECTED}
    SHELLS="/bin/sh /bin/bash"

    if [ -r "${ROOTDIR}etc/shells" ]; then
        SHELLS=$(${egrep} -v '^#' "${ROOTDIR}etc/shells")
    fi

    if [ -r "${ROOTDIR}etc/inetd.conf" ]; then
        INETD_CONF_LINES=$(${egrep} -v '^#' "${ROOTDIR}etc/inetd.conf")
        for CHK_SHELL in ${SHELLS}; do
            if "${echo}" "$INETD_CONF_LINES" | ${egrep} -q "stream.*tcp.*nowait.*$CHK_SHELL" 2>/dev/null; then
                if [ "${EXPERT}" = "t" ]; then
                    echo "Backdoor shell record(s) in /etc/inetd.conf: "
                    ${egrep} -v "^#" "${ROOTDIR}etc/inetd.conf" | ${egrep} "^.*stream.*tcp.*nowait.*$CHK_SHELL.*"
                    # other chk_* functions return 5 here (?)
                fi
                return "${INFECTED}"
            fi
        done
        return "${STATUS}"
    else
        return "${NOT_FOUND}"
    fi
}

chk_telnetd () {
    STATUS=${NOT_INFECTED}
    TELNETD_INFECTED_LABEL='cterm100|vt350|VT100|ansi-term|/dev/hda[0-7]'
    CMD=$(loc telnetd telnetd "$pth")

    if [ ${?} -ne 0 ]; then
        CMD=$(loc in.telnetd in.telnetd "$pth")
        if [ ${?} -ne 0 ]; then
            return "${NOT_FOUND}"
        fi
    fi

    if [ "${EXPERT}" = "t" ]; then
        expertmode_output "${strings} -a ${CMD}"
        return 5
    fi

    if "${strings}" -a "${CMD}" | ${egrep} "${TELNETD_INFECTED_LABEL}" \
       >/dev/null 2>&1
    then
        STATUS=${INFECTED}
    fi
    return "${STATUS}"
}

printn ()
{
    printf="use printf"
    printf_fmt="%-60s"

    if [ -z "$PRINTF_BIN" ]; then
	    # This is first time call to use. Check environment and
	    # define this global.

	    PRINTF_BIN=$(which printf 2> /dev/null)

	    # Set to dummy, if not found
	    [ -z "$PRINTF_BIN" ] && PRINTF_BIN="not exists"

	    # We're done, and won't enter this if-case any more
    fi

    # Some messages are continued, so don't use PRINTF_BIN
    case "$1" in
	    *exec*|*bogus*) printf="" ;;
    esac

    if [ -n "$PRINTF_BIN" ] && [ -n "$printf" ]; then
	    "$PRINTF_BIN" "$printf_fmt" "$1"
    else
	    if "${echo}" "a\c" | ${egrep} c >/dev/null 2>&1 ; then
	        "${echo}" -n "$1"
	    else
	        "${echo}" "${1}\c"
	    fi
    fi
}

# main
#


### using regexps, as the `-w' option to grep/egrep is not portable.
L_REGEXP='(^|[^A-Za-z0-9_])'
R_REGEXP='([^A-Za-z0-9_]|$)'

### default ROOTDIR is "/"
ROOTDIR='/'
mode="rt"

findargs=""

EXPERT=""
QUIET=""
QUIET_ARG=""
EXCLUDES=""
EXCLUDES_SNIF=""

while :
do
        case "${1-}" in
        -r)    [ -z "$2" ] && exit 1;
               shift
               mode="pm"
               ROOTDIR=$1;;
        -p)    [ -z "$2" ] && exit 1;
                shift
                CHKRKPATH=$1;;

        -d)     DEBUG=t;;

        -x)     EXPERT=t;;

        -e)     shift
                findargs="${findargs} -path $1 -prune -o"
                EXCLUDES="$EXCLUDES $1";;

        -s)     shift
                EXCLUDES_SNIF="$1";;

        -q)     QUIET=t
                QUIET_ARG="-q"
                ;;

        -V)     echo >&2 "chkrootkit version ${CHKROOTKIT_VERSION}"
                exit 1;;

        -l)     echo >&2 "$0: tests: ${TOOLS} ${TROJAN}"
                exit 1;;

        -n)     exclude_fstype nfs;;

        -T)     shift
                exclude_fstype "$1";;

        -h | -*) echo >&2 "Usage: $0 [options] [test ...]
Options:
        -h                show this help and exit
        -V                show version information and exit
        -l                show available tests and exit
        -d                debug
        -q                quiet mode
        -x                expert mode
        -e 'FILE1 FILE2'  exclude files/dirs from results. Must be followed by a space-separated list of files/dirs.
                          Read /usr/share/doc/chkrootkit/README.FALSE-POSITIVES first.
        -s REGEXP         filter results of sniffer test through 'grep -Ev REGEXP' to exclude expected
                          PACKET_SNIFFERs. Read /usr/share/doc/chkrootkit/README.FALSE-POSITIVES first.
        -r DIR            use DIR as the root directory
        -p DIR1:DIR2:DIRN path for the external commands used by chkrootkit
        -n                skip NFS mount points
        -T FSTYPE         skip mount points of the specified file system type"
                exit 1;;
        *)      break
        esac

        shift
done

### check the external commands needed

cmdlist="
awk
cut
echo
grep
find
head
id
ls
ps
sed
strings
uname
xargs
"

### PATH used by loc
pth=$(echo "$PATH" | sed -e "s/:/ /g")
pth="$pth /sbin /usr/sbin /lib /usr/lib /usr/libexec ."

### external (trusted) command's PATH
if [ "${CHKRKPATH}" = "" ]; then
		chkrkpth=${pth}
		path_for_tools="$PATH"
else
		### use the path provided with the -p option
		chkrkpth=$(echo "${CHKRKPATH}" | sed -e "s/:/ /g")
		# chkutmp and chkproc assume 'ps' from $PATH is safe to run
		path_for_tools="$CHKRKPATH:$PATH"
fi
for file in $cmdlist; do
        xxx=$(loc "$file" "$file" "$chkrkpth")
        eval "$file=$xxx"
        case "$xxx" in
        /* | ./* | ../*)

                if [ ! -x "${xxx}" ]
                then
                    echo >&2 "chkrootkit: can't exec \`$xxx'."
                    exit 1
                fi
                ;;
        *)
                echo >&2 "chkrootkit: can't find \`$file'."
                exit 1
                ;;
        esac
done
egrep="${grep} -E"
if [ "${mode}" = "rt" ]; then
    dpkg_query=$(loc dpkg-query "" "$chkrkpth")
else
    dpkg_query=""
fi
if [ -n "${dpkg_query}" ] && [ ! -x "${dpkg_query}" ]; then
    # unlikely
    echo >&2 "chkrootkit: can't exec dpkg-query: \`${dpkg_query}'."
    exit 1
fi

# check if $1 is excluded by $EXCLUDES. $2 is the previous results. Use as
#  results=$(_filter "$f" "$results")
# which appends f to $results unless f is excluded.
_filter(){
    file_to_report="$1"
    prev_results="$2"
    if [ -n "$prev_results" ]; then
        echo "$prev_results"
    fi
    # We need $EXCLUDES to not be a glob, but its componants
    # (eg /usr/*) to be globbed, so $exclude is unquoted below.
    # And we need to reset 'set +f' in both return paths in case
    # we are not run in a subshell
    set -f
    for exclude in $EXCLUDES; do
        case "$file_to_report" in
            $exclude) set +f; return 0 ;;
        esac
    done
    set +f
    __filter "$file_to_report"
}

if [ -n "${dpkg_query}" ]; then
    find_and_check(){
        "${find}" "$@" -print0 2>/dev/null | PATH="$path_for_tools" "${xargs}" -0 -I@ ./check_if_debian @ "${dpkg_query}"
    }

    __filter(){
        PATH="$path_for_tools" ./check_if_debian "$1" "${dpkg_query}"
    }
else
    # non-Debian or using -r
    find_and_check(){
        "${find}" "$@" -print 2>/dev/null
    }

    __filter(){
        echo "$1"
    }
fi


SYSTEM=$("${uname}" -s)
VERSION=$("${uname}" -r)
if [ "${SYSTEM}" != "FreeBSD" -a "${SYSTEM}" != "OpenBSD" ] ; then
   V=4.4
else
   V=$(echo "$VERSION"| "${sed}" -e 's/[-_@].*//'| "${awk}" -F . '{ print $1 "." $2 $3 }')
fi

# head command
_head()
{
   if "${echo}" a | "${head}" -n 1 >/dev/null 2>&1; then
      "${head}" -n "$(echo "$1" | tr -d "-")"
   else
      "${head}" "$1"
   fi
}
# ps command
ps_cmd="ax"
if [ "$SYSTEM" = "SunOS" ]; then
  if [ "${CHKRKPATH}" = "" ]; then
    if [ -x /usr/ucb/ps ]; then
       ps="/usr/ucb/ps"
    else
       ps_cmd="-fe"
    fi
  else
    ### -p is in place: use `-fe' as ps options
    ps_cmd="-fe"
  fi
fi
# Check if ps command is ok
if "${ps}" ax >/dev/null 2>&1 ; then
   ps_cmd="ax"
else
   ps_cmd="-fe"
fi

if [ "$("${id}" | "${cut}" -d= -f2 | "${cut}" -d\( -f1)" -ne 0 ]; then
   echo "$0 needs root privileges: some checks may not work"
fi

if [ $# -gt 0 ]
then
    ### perform only tests supplied as arguments
    for arg in "$@"
    do
        ### check if is a valid test name
        if echo "${TROJAN} ${TOOLS}"| \
           ${egrep} -v "${L_REGEXP}$arg${R_REGEXP}" > /dev/null 2>&1
        then
            echo >&2 "$0: \`$arg': not a known test"
            exit 1
        fi
    done
    LIST=$*
else
    ### this is the default: perform all tests
    LIST="${TROJAN} ${TOOLS}"
fi

if [ "${DEBUG}" = "t" ]; then
    set -x
fi

if [ "${ROOTDIR}" != "/" ]; then

    ### remove trailing `/'
    ROOTDIR=$(echo "${ROOTDIR}" | "${sed}" -e 's/\/*$//g')

    newpth=""
    for dir in ${pth}
    do
      if echo "${dir}" | ${egrep} '^/' > /dev/null 2>&1
      then
        newpth="${newpth} ${ROOTDIR}${dir}"
      else
        newpth="${newpth} ${ROOTDIR}/${dir}"
      fi
    done
    pth=${newpth}
    ROOTDIR="${ROOTDIR}/"
fi
if [ "${QUIET}" != "t" ]; then
    echo "ROOTDIR is \`${ROOTDIR}'"
fi
#
# NETSTAT OR SS
#
_chk_netstat_or_ss()
{
    netstat=$(loc ss ss "$chkrkpth")
    [ ${?} -eq 0 ] || netstat=$(loc netstat netstat "$chkrkpth")
}

for cmd in ${LIST}
do
    if echo "${TROJAN}" | \
    ${egrep} "${L_REGEXP}$cmd${R_REGEXP}" > /dev/null 2>&1
    then
        if [ "${EXPERT}" != "t" -a "${QUIET}" != "t" ]; then
            printn "Checking \`${cmd}'... "
        fi
        # each chk_xxx function should not produce any output (unless in EXPERT mode)
        "chk_${cmd}"
        STATUS=$?
        ### quiet mode
        if [ "${QUIET}" = "t" ]; then
            ### show only if INFECTED status
            if [ "${STATUS}" -eq "${INFECTED}" ]; then
                echo "Checking \`${cmd}'... INFECTED"
            fi
        else
            case $STATUS in
                "$INFECTED") echo "INFECTED";;
                "$NOT_INFECTED") echo "not infected";;
                "$NOT_TESTED") echo "not tested";;
                "$NOT_FOUND") echo "not found";;
                "$INFECTED_BUT_DISABLED") echo "INFECTED but disabled";;
                5) ;;   ### expert mode
            esac
        fi
    else
        ### external tool
        if [ "${EXPERT}" != "t" -a "${QUIET}" != "t" ]; then
            printn "Checking \`$cmd'... "
        fi
        # unlike the chk_* functions, the functions in $TOOLS are expected to handle $QUIET
        "${cmd}"
    fi
done
exit 0
### chkrootkit ends here.
