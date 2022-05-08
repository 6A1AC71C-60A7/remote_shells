#bin/sh

CC=gcc
KEY=1234
PORT=6047

TARGET_SHELL=remote_shell_serv.c
FLAGS_SHELL="-nostdlib -lgcc -Wall -Wextra -Werror -o"
NAME_SHELL="shell"

LOCK_TLS="/tmp/123"
LOCK_SHELL="/tmp/987"

TARGET_TRANSFORM=transform.c
FLAGS_TRANSFORM="-Wall -Wextra -Werror -o"
NAME_TRANSFORM="transform"

# Clean up
rm $NAME_SHELL $NAME_TRANSFORM 2> /dev/null
echo "> rm ${NAME_SHELL} ${NAME_TRANSFORM} "
killall $NAME_SHELL 2> /dev/null
echo "> killall ${NAME_SHELL}"

# Compile shell
$CC $FLAGS_SHELL $NAME_SHELL $TARGET_SHELL
echo "> ${CC} ${FLAGS_SHELL} ${NAME_SHELL} ${TARGET_SHELL}"

# Compile transform
$CC $FLAGS_TRANSFORM $NAME_TRANSFORM $TARGET_TRANSFORM
echo "> ${CC} ${FLAGS_TRANSFORM} ${NAME_TRANSFORM} ${TARGET_TRANSFORM}"

# Clear locks
rm $LOCK_TLS $LOCK_SHELL 2> /dev/null
echo "> rm ${LOCK_SHELL} ${LOCK_TLS}"

echo "USAGE: LAUNCH REMOTE SHELL: ./${NAME_SHELL}"
echo "USAGE: LAUNCH CLIENT: ./${NAME_TRANSFORM} -e ${KEY} | netcat \$TARGET_IP ${PORT} | ./${NAME_TRANSFORM} -d ${KEY}"
echo "NOTE: REMEMBER THAT ./${NAME_SHELL} IS A PERSISTENT PROCESS AND SHOULD BE KILLED AFTER TESTING !"
