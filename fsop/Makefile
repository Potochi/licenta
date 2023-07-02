cold_simple: cold_storage.c
	gcc \
    -Wall \
    -Wextra \
    -Wl,-z,relro,-z,now \
    -Wconversion \
    -fstack-protector-all \
    -Werror \
    -no-pie \
    -fno-pic \
    -D_FORTIFY_SOURCE=2 \
    -g \
    -O2 \
    cold_storage.c -o cold_simple

cold_sanitized: cold_storage.c
	clang \
    -Wall \
    -Wextra \
    -Wl,-z,relro,-z,now \
    -Wconversion \
    -fstack-protector-all \
    -fsanitize=address,undefined,bounds,array-bounds\
    -Werror \
    -no-pie \
    -fno-pic \
    -D_FORTIFY_SOURCE=3 \
    -g \
    -O2 \
    cold_storage.c -o cold_sanitized

